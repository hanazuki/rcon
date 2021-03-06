module rcon;

import std.algorithm: map;
import std.array: Appender, replace, join, split, popFront, front;
import std.file: readText;
import std.getopt: getopt, config;
import std.socket: Socket, SocketException, SocketType, ProtocolType, getAddressInfo;
import std.socketstream: SocketStream;
import std.stdio: File, stdout, stdin, stderr;
import std.stream: Stream, EndianStream;
import std.string: strip;
import std.system: Endian;

version(Posix) {
  extern(C) int isatty(int fd) @system;
  bool isatty(File file) @trusted {
    import core.stdc.stdio: fileno;
    return isatty(fileno(file.getFP)) == 1;
  }
} else {
  static assert(false, "non-Posix platforms are not supported.");
}

shared int verbose = 0;

class RCon {
private:
  Stream endpoint;
  int sequence = 0;

  enum SERVERDATA_RESPONSE_VALUE = 0,
    SERVERDATA_EXECCOMMAND = 2,
    SERVERDATA_AUTH_RESPONSE = 2,
    SERVERDATA_AUTH = 3;

  static Socket connect(string host, string service) {
    if(verbose > 0) stderr.writefln("connecting to server %s:%s", host, service);
    foreach(addrinfo; getAddressInfo(host, service, SocketType.STREAM, ProtocolType.TCP)) {
      try {
        if(verbose > 1) stderr.writefln("connect: %s", addrinfo);
        auto socket = new Socket(addrinfo);
        scope(failure) socket.close();
        socket.connect(addrinfo.address);
        return socket;
      } catch(SocketException ex) {
        if(verbose > 1) stderr.writefln("connection failed (%s)", ex.msg);
      }
    }
    throw new RConException("connection failure");
  }

  static struct Packet {
    int id, type;
    char[] content;

    void write(Stream sink) const {
      int len = cast(int)(content.length + 10);
      sink.write(len);
      sink.write(id);
      sink.write(type);
      sink.writeExact(content.ptr, content.length);
      sink.write('\0');
      sink.write('\0');
    }

    void read(Stream source) {
      int len = void;
      source.read(len);
      source.read(id);
      source.read(type);
      content = new char[](len - 10);
      source.readExact(content.ptr, content.length);
      source.getc(); // '\0'
      source.getc(); // '\0'
    }

    /// serialization and deserialization
    unittest {
      import std.stream: MemoryStream;

      enum packetId = 0xDEADBEEF;
      enum packetType = SERVERDATA_AUTH;
      enum packetContent = "steam";

      auto packet = const(Packet)(packetId, packetType, packetContent);

      auto stream = new MemoryStream;
      packet.write(stream);

      assert(stream.data.length == 12+packetContent.length+2);
      assert(stream.data[0..4] == [4+4+packetContent.length+2, 0, 0, 0]); // len
      assert(stream.data[4..8] == [0xEF, 0xBE, 0xAD, 0xDE]); // id
      assert(stream.data[8..12] == [packetType, 0, 0, 0]); // type
      assert(stream.data[12..12+packetContent.length] == cast(immutable(ubyte)[])packetContent);
      assert(stream.data[12+packetContent.length] == 0);
      assert(stream.data[12+packetContent.length+1] == 0);

      Packet packet0 = void;
      stream.seekSet(0);
      packet0.read(stream);

      assert(packet == packet0);
    }
  }

  void send(const(Packet) packet) {
    if(verbose > 2) stderr.writefln("send: %s", packet);
    packet.write(endpoint);
    endpoint.flush();
  }

  Packet recv() {
    typeof(return) packet = void;
    packet.read(endpoint);
    if(verbose > 2) stderr.writefln("recv: %s", packet);
    return packet;
  }

public:
  enum defaultService = "27015";

  this(string host, string service) {
    auto socket = connect(host, service);
    endpoint = new EndianStream(new SocketStream(socket), Endian.littleEndian);
  }

  void close() {
    endpoint.close();
  }

  void login(string password) {
    if(verbose > 1) stderr.writeln("sending password to server");
    send(const(Packet)(0xCAFE, SERVERDATA_AUTH, password));

    if(verbose > 1) stderr.writeln("receiving response for auth");
    auto res = recv();
    if(res.id != 0xCAFE || res.type != SERVERDATA_RESPONSE_VALUE) {
      throw new RConException("authentication failure");
    }
    res = recv();
    if(res.id != 0xCAFE || res.type != SERVERDATA_AUTH_RESPONSE) {
      throw new RConException("authentication failure");
    }

    if(verbose > 0) stderr.writeln("login succeeded");
  }

  string execute(string command) {
    immutable seq = sequence++;

    if(verbose > 1) stderr.writeln("sending command to server");
    send(const(Packet)(seq, SERVERDATA_EXECCOMMAND, command));
    send(const(Packet)(seq, SERVERDATA_RESPONSE_VALUE, ""));

    Appender!string result;

    if(verbose > 1) stderr.writeln("receiving response for command");
    for(;;) {
      auto res = recv();

      if(res.id != seq || res.type != SERVERDATA_RESPONSE_VALUE) {
        throw new RConException("execution failure");
      }

      if(res.content == "\0\1\0\0") break;
      result ~= res.content;
    }

    return result.data;
  }

  static class RConException : Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__, Throwable next = null) {
      super(msg, file, line, next);
    }
  }
}

bool parseHost(string hostSpec, ref string host, ref string port) {
  auto pair = hostSpec.split(":");
  switch(pair.length) {
  case 2:
    port = pair[1];
    // fallthrough
  case 1:
    host = pair[0];
    return true;
  default:
    return false;
  }
}

void main(string[] args) {
  string password, host, port = RCon.defaultService;
  try {
    getopt(args,
           config.caseSensitive,
           config.bundling,
           config.stopOnFirstNonOption,
           "verbose|v", (){ ++verbose; },
           "password|p", &password,
           "password-from|P", (string _, string path) {
             password = readText(path).strip;
           });
    args.popFront();
    if(args.length == 0 || !args.front.parseHost(host, port)) {
      throw new Exception("A HOST must be specified");
    }
    args.popFront;
  } catch(Exception ex) {
    stderr.writeln(ex.msg);
    stderr.writeln("Usage: rcon [-vvv] (-P PASSFILE|-p PASSWORD) HOST[:PORT] [COMMAND]");
    return;
  }

  try {
    auto rcon = new RCon(host, port);
    scope(exit) rcon.close();

    rcon.login(password);

    if(args.length > 0) {
      auto cmdline = args.map!(word => '"' ~ word.replace(`"`, `\"`) ~ '"').join(" ");
      stdout.write(rcon.execute(cmdline));
    } else {
      while(true) {
        if(isatty(stdin)) {
          stdout.write("> "), stdout.flush();
        }
        auto line = stdin.readln();
        if(line is null) break;
        stdout.write(rcon.execute(line.strip));
      }
    }
  } catch(Exception ex) {
    stderr.writeln(ex.msg);
  }
}
