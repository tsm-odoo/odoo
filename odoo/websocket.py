import base64
import functools
import hashlib
import json
import logging
import queue
import socket
import struct
import threading
import time
from collections import defaultdict
from contextlib import suppress
from enum import IntEnum
from itertools import count
from sys import float_info
from werkzeug.exceptions import BadRequest, HTTPException

import odoo.service.server as servermod
from odoo.http import Response

_logger = logging.getLogger(__name__)

# ------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------


class UpgradeRequired(HTTPException):
    code = 426
    description = "Wrong websocket version was given during the handshake"

    def get_headers(self, environ=None):
        headers = super().get_headers(environ)
        headers.append(
            ('Sec-WebSocket-Version', '; '.join(WebsocketConnectionHandler.SUPPORTED_VERSIONS)))
        return headers


class WebsocketException(Exception):
    """ Base class for all websockets exceptions """


class ConnectionClosed(WebsocketException):
    """ Raised when the other end closes the socket """


class InvalidCloseCodeException(WebsocketException):
    def __init__(self, code):
        super().__init__(f"Invalid close code: {code}")


class InvalidStateException(WebsocketException):
    """ Raised when an operation is forbidden in the current state """


class ProtocolError(WebsocketException):
    """ Raised when a frame format doesn't match expectations """


# ------------------------------------------------------
# WEBSOCKET
# ------------------------------------------------------


class LifecycleEvent(IntEnum):
    ONOPEN = 0
    ONCLOSE = 1


class Opcode(IntEnum):
    CONTINUE = 0x00
    TEXT = 0x01
    BINARY = 0x02
    CLOSE = 0x08
    PING = 0x09
    PONG = 0x0A


class CloseCode(IntEnum):
    CLEAN = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    INCORRECT_DATA = 1003
    ABNORMAL_CLOSURE = 1006
    INCONSISTENT_DATA = 1007
    MESSAGE_VIOLATING_POLICY = 1008
    MESSAGE_TOO_BIG = 1009
    EXTENSION_NEGOTIATION_FAILED = 1010
    SERVER_ERROR = 1011
    RESTART = 1012
    TRY_LATER = 1013
    BAD_GATEWAY = 1014


class ConnectionState(IntEnum):
    OPEN = 0
    CLOSING = 1
    CLOSED = 2


DATA_OP = {Opcode.TEXT, Opcode.BINARY}
CTRL_OP = {Opcode.CLOSE, Opcode.PING, Opcode.PONG}
VALID_CLOSE_CODES = {code for code in CloseCode if code is not CloseCode.ABNORMAL_CLOSURE}
CLEAN_CLOSE_CODES = {CloseCode.CLEAN, CloseCode.GOING_AWAY, CloseCode.RESTART}
RESERVED_CLOSE_CODES = range(3000, 5000)
# Used to fasten _apply_mask method (which is the most time consuming operation when receiving a
# frame)
_XOR_TABLE = [bytes(a ^ b for a in range(256)) for b in range(256)]


@functools.total_ordering
class Frame:
    """ This class implements the `__lt__` method in order for frames to be stored in a
    `PriorityQueue`. Priorities are, in order (FIFO if same priority): close, other control opcodes,
    data opcodes. see: https://datatracker.ietf.org/doc/html/rfc6455#section-5.2.
    """
    _frames_sent = count(0)

    def __init__(self, opcode, payload=b'', fin=True, rsv1=False, rsv2=False, rsv3=False):
        self._send_order = next(self._frames_sent)
        self.opcode = opcode
        self.payload = payload
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3

    def __eq__(self, other):
        if not isinstance(other, Frame):
            return False
        return other.opcode == self.opcode and self.payload == other.payload

    def __lt__(self, other):
        if not isinstance(other, Frame):
            raise TypeError("< only supported between instances of 'Frame'")
        if (self.opcode in CTRL_OP and other.opcode in CTRL_OP
                or self.opcode in DATA_OP and other.opcode in DATA_OP):
            return self.opcode is Opcode.CLOSE or self._send_order < other._send_order
        return self.opcode in CTRL_OP


class Websocket:
    _onevent_funcs = defaultdict(set)

    def __init__(self, socket):
        self._socket = socket
        self.state = ConnectionState.OPEN
        self._outgoing_frames_queue = queue.PriorityQueue()
        self._outgoing_frames_consumer = threading.Thread(target=self._consume_outgoing_frames)
        self._outgoing_frames_consumer.start()
        self._timeout_manager = TimeoutManager(self)
        self._timeout_manager.start()
        if servermod.server:
            servermod.server.on_stop(self._on_server_stop)
        for func in Websocket._onevent_funcs[LifecycleEvent.ONOPEN]:
            func(self)

    # ------------------------------------------------------
    # PUBLIC METHODS
    # ------------------------------------------------------

    def get_messages(self):
        initial_opcode, message_fragments = None, bytearray()
        try:
            while self.state is not ConnectionState.CLOSED:
                frame = self._get_next_frame()
                if frame.opcode in CTRL_OP:
                    # Control frames can be received in the middle of a fragmented message, process
                    # them as soon as possible.
                    self._handle_control_frame(frame)
                    continue
                if frame.opcode is Opcode.CONTINUE and not initial_opcode:
                    raise ProtocolError("Unexpected continuation frame")
                if frame.opcode in DATA_OP and initial_opcode:
                    raise ProtocolError("A continuation frame was expected")
                initial_opcode = frame.opcode if frame.opcode in DATA_OP else initial_opcode
                if not frame.fin or frame.opcode is Opcode.CONTINUE:
                    message_fragments.extend(frame.payload)
                if frame.fin:
                    # Yield the concatenation of all the fragments if the message was fragmented,
                    # the frame payload otherwise.
                    whole_msg = message_fragments if frame.opcode is Opcode.CONTINUE else frame.payload
                    yield whole_msg.decode('utf-8') if initial_opcode is Opcode.TEXT else bytes(whole_msg)
                    initial_opcode, message_fragments = None, bytearray()
        except Exception as exc:
            self._handle_exception(exc)

    def send(self, message):
        if self.state is not ConnectionState.OPEN:
            raise InvalidStateException("Trying to send frame on a closed socket")
        opcode = Opcode.BINARY
        if not isinstance(message, (bytes, bytearray)):
            opcode = Opcode.TEXT
        self._outgoing_frames_queue.put(Frame(opcode, message))

    def disconnect(self, code, reason=None):
        reason = None if code is CloseCode.SERVER_ERROR else reason
        # Don't send close frame if connection has been closed abruptly.
        if code is not CloseCode.ABNORMAL_CLOSURE:
            self._send_close(code, reason)
        if code not in CLEAN_CLOSE_CODES:
            # Fail the connection: wait for the close frame to be sent before terminating.
            if (code is not CloseCode.ABNORMAL_CLOSURE and
                    threading.current_thread() is not self._outgoing_frames_consumer):
                self._outgoing_frames_consumer.join()
            self._terminate()

    @classmethod
    def onopen(cls, func):
        cls._onevent_funcs[LifecycleEvent.ONOPEN].add(func)

    @classmethod
    def onclose(cls, func):
        cls._onevent_funcs[LifecycleEvent.ONCLOSE].add(func)

    # ------------------------------------------------------
    # PRIVATE METHODS
    # ------------------------------------------------------

    def _get_next_frame(self):
        #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #    +-+-+-+-+-------+-+-------------+-------------------------------+
        #    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        #    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        #    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        #    | |1|2|3|       |K|             |                               |
        #    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        #    |     Extended payload length continued, if payload len == 127  |
        #    + - - - - - - - - - - - - - - - +-------------------------------+
        #    |                               |Masking-key, if MASK set to 1  |
        #    +-------------------------------+-------------------------------+
        #    | Masking-key (continued)       |          Payload Data         |
        #    +-------------------------------- - - - - - - - - - - - - - - - +
        #    :                     Payload Data continued ...                :
        #    + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        #    |                     Payload Data continued ...                |
        #    +---------------------------------------------------------------+
        def recv_bytes(n):
            """ Pull n bytes from the socket """
            data = bytearray()
            while len(data) < n:
                received_data = self._socket.recv(n - len(data))
                if not received_data:
                    raise ConnectionClosed()
                data.extend(received_data)
            return data

        def is_bit_set(byte, n):
            """ Check whether nth bit of byte is set or not (from left to right) """
            return byte & (1 << (7 - n))

        def apply_mask(payload, mask):
            # see: https://www.willmcgugan.com/blog/tech/post/speeding-up-websockets-60x/
            a, b, c, d = (_XOR_TABLE[n] for n in mask)
            payload[::4] = payload[::4].translate(a)
            payload[1::4] = payload[1::4].translate(b)
            payload[2::4] = payload[2::4].translate(c)
            payload[3::4] = payload[3::4].translate(d)
            return payload

        first_byte, second_byte = struct.unpack('!BB', recv_bytes(2))
        fin, rsv1, rsv2, rsv3 = (is_bit_set(first_byte, n) for n in range(4))
        try:
            opcode = Opcode(first_byte & 0b00001111)
        except ValueError as exc:
            raise ProtocolError(exc)
        payload_length = second_byte & 0b01111111

        if rsv1 or rsv2 or rsv3:
            raise ProtocolError("Reserved bits must be unset")
        if not is_bit_set(second_byte, 0):
            raise ProtocolError("Frame must be masked")
        if opcode in CTRL_OP:
            if not fin:
                raise ProtocolError("Control frames cannot be fragmented")
            if payload_length > 125:
                raise ProtocolError("Control frames must have a payload length smaller than 126")

        if payload_length == 126:
            payload_length = struct.unpack('!H', recv_bytes(2))[0]
        elif payload_length == 127:
            payload_length = struct.unpack('!Q', recv_bytes(8))[0]
        mask = recv_bytes(4)
        payload = apply_mask(recv_bytes(payload_length), mask)
        self._timeout_manager.acknowledge_frame_receipt()
        return Frame(opcode, bytes(payload), fin, rsv1, rsv2, rsv3)

    def _send_frame(self, frame):
        if frame.opcode in CTRL_OP and len(frame.payload) > 125:
            raise ProtocolError("Control frames should have a payload length smaller than 126")

        if isinstance(frame.payload, str):
            frame.payload = frame.payload.encode('utf-8')
        elif not isinstance(frame.payload, (bytes, bytearray)):
            frame.payload = json.dumps(frame.payload).encode('utf-8')

        output = bytearray()
        first_byte = (
            (0b10000000 if frame.fin else 0)
            | (0b01000000 if frame.rsv1 else 0)
            | (0b00100000 if frame.rsv2 else 0)
            | (0b00010000 if frame.rsv3 else 0)
            | frame.opcode
        )
        second_byte = 0
        payload_length = len(frame.payload)
        if payload_length < 126:
            output.extend(struct.pack('!BB', first_byte, second_byte | payload_length))
        elif payload_length < 65536:
            output.extend(struct.pack('!BBH', first_byte, second_byte | 126, payload_length))
        else:
            output.extend(struct.pack('!BBQ', first_byte, second_byte | 127, payload_length))
        output.extend(frame.payload)
        self._socket.sendall(output)

    def _send_close(self, code, reason=None):
        if code not in VALID_CLOSE_CODES and code not in RESERVED_CLOSE_CODES:
            raise InvalidCloseCodeException(code)
        # CPython switches thread every 5ms, when a data frame and a close frame are added to the
        # queue in this interval, the data frame won't be sent because the close frame have
        # priority. This is not a serious issue, but this makes the autobahn test suite pass some
        # tests with a non-strict behavior. Sleeping for the smallest amount of time allows the
        # consumer's coroutine to be executed first which solves this issue.
        time.sleep(float_info.epsilon)
        payload = struct.pack('!H', code)
        if reason:
            payload += reason.encode('utf-8')
        self._outgoing_frames_queue.put(Frame(Opcode.CLOSE, payload))

    def _send_ping(self):
        self._outgoing_frames_queue.put(Frame(Opcode.PING))

    def _send_pong(self, payload):
        self._outgoing_frames_queue.put(Frame(Opcode.PONG, payload))

    def _terminate(self):
        with suppress(OSError):
            self._socket.shutdown(socket.SHUT_WR)
            # Call recv until obtaining a return value of 0 indicating the other end has performed
            # an orderly shutdown.
            remaining_data = self._socket.recv(4096)
            while remaining_data:
                remaining_data = self._socket.recv(4096)
        self._socket.close()
        self.state = ConnectionState.CLOSED
        self._timeout_manager.stop()
        if servermod.server:
            servermod.server.off_stop(self._on_server_stop)
        for func in Websocket._onevent_funcs[LifecycleEvent.ONCLOSE]:
            func(self)

    def _handle_control_frame(self, frame):
        if frame.opcode is Opcode.PING:
            self._send_pong(frame.payload)
        elif frame.opcode is Opcode.CLOSE:
            is_client_initiated = self.state is ConnectionState.OPEN
            self.state = ConnectionState.CLOSING
            code, reason = CloseCode.CLEAN, None
            if len(frame.payload) >= 2:
                code = struct.unpack('!H', frame.payload[:2])[0]
                reason = frame.payload[2:].decode('utf-8')
            elif frame.payload:
                raise ProtocolError("Malformed closing frame")
            if is_client_initiated:
                self._send_close(code, reason)
                self._outgoing_frames_consumer.join()
            self._terminate()

    def _handle_exception(self, exc):
        """ Find out which close code we should send according to given exception and call
        `self.disconnect` in order to close the connection cleanly.
        """
        if self.state is ConnectionState.CLOSED:
            return
        code, reason = CloseCode.SERVER_ERROR, str(exc)
        if isinstance(exc, (ConnectionClosed, OSError)):
            code = CloseCode.ABNORMAL_CLOSURE
        elif isinstance(exc, (ProtocolError, InvalidCloseCodeException)):
            code = CloseCode.PROTOCOL_ERROR
        elif isinstance(exc, UnicodeDecodeError):
            code = CloseCode.INCONSISTENT_DATA
        if code is CloseCode.SERVER_ERROR:
            _logger.error(exc, exc_info=True)
        self.disconnect(code, reason)

    def _on_server_stop(self):
        self.disconnect(CloseCode.GOING_AWAY)

    def _consume_outgoing_frames(self):
        while self.state is not ConnectionState.CLOSED:
            try:
                frame = self._outgoing_frames_queue.get(timeout=5)
            except queue.Empty:
                continue
            if self.state is not ConnectionState.CLOSED:
                try:
                    self._send_frame(frame)
                    if frame.opcode is Opcode.CLOSE:
                        self.state = ConnectionState.CLOSING
                        # An endpoint must not send anything after sending a close frame
                        break
                except (OSError, UnicodeEncodeError) as exc:
                    self._handle_exception(exc)


class TimeoutManager(threading.Thread):
    """ Send pings every HEARTBEAT_DELAY seconds if no other frames have been sent during this
    period. If no answer is received TIMEOUT seconds after a ping/close frame, close the connection.
    """
    HEARTBEAT_DELAY = 50
    TIMEOUT = 15

    def __init__(self, websocket):
        super().__init__()
        self._websocket = websocket
        self._event = threading.Event()
        self._exit = False

    def run(self):
        while not self._exit:
            self._event.wait(self.HEARTBEAT_DELAY)
            if not self._event.is_set():
                # No frame has been received during the heartbeat_delay, if the state is not OPEN,
                # we are waiting for a close frame.
                if self._websocket.state is ConnectionState.OPEN:
                    self._websocket._send_ping()
                self._event.wait(self.TIMEOUT)
                if not self._event.is_set():
                    self._websocket.disconnect(CloseCode.ABNORMAL_CLOSURE)
            self._event.clear()

    def acknowledge_frame_receipt(self):
        # Reset the heartbeat only if we are not waiting for a close frame.
        if self._websocket.state is ConnectionState.OPEN:
            self._event.set()

    def stop(self):
        self._exit = True
        self._event.set()

# ------------------------------------------------------
# WEBSOCKET SERVING
# ------------------------------------------------------


class WebsocketConnectionHandler:
    SUPPORTED_VERSIONS = {'13'}
    # Given by the RFC in order to generate Sec-WebSocket-Accept from Sec-WebSocket-Key value.
    _HANDSHAKE_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    _REQUIRED_HANDSHAKE_HEADERS = {
        'connection', 'upgrade', 'host', 'sec-websocket-key', 'sec-websocket-version'
    }

    @classmethod
    def get_handshake_response(cls, headers):
        """ :return: Response indicating the server performed a connection upgrade :raise:
            BadRequest :raise: UpgradeRequired
        """
        cls._ensure_handshake_validity(headers)
        # sha-1 is used as it is required by https://datatracker.ietf.org/doc/html/rfc6455#page-7
        accept_header = hashlib.sha1((
            headers['sec-websocket-key'] + cls._HANDSHAKE_GUID).encode()).digest()
        accept_header = base64.b64encode(accept_header)
        return Response(status=101, headers={
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Accept': accept_header,
        })

    @classmethod
    def _ensure_handshake_validity(cls, headers):
        """ :raise: UpgradeRequired if there is no intersection between the version the client
            supports and those we support :raise: BadRequest in case of invalid handshake
        """
        missing_or_empty_headers = {header for header in cls._REQUIRED_HANDSHAKE_HEADERS
                                    if not headers.get(header)}
        if missing_or_empty_headers:
            raise BadRequest(f"Empty or missing header(s): {', '.join(missing_or_empty_headers)}")
        if (headers['upgrade'].lower() != 'websocket'
                or 'upgrade' not in headers['connection'].lower()):
            raise BadRequest(
                "Upgrade, Connection should have a value of websocket and upgrade, respectively")

        key = headers['sec-websocket-key']
        try:
            decoded_key = base64.b64decode(key)
        except ValueError:
            raise BadRequest("Sec-WebSocket-Key should be b64 encoded")
        if len(decoded_key) != 16:
            raise BadRequest("Sec-WebSocket-Key should be of length 16 once decoded")

        if headers['sec-websocket-version'] not in cls.SUPPORTED_VERSIONS:
            raise UpgradeRequired()
