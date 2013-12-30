module rcon;

import std.algorithm: map;
import std.array: replace, join, split, popFront, front;
import std.exception: assumeUnique;
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

  Socket connect(string host, string service) {
    if(verbose > 0) stderr.writefln("connecting to server %s:%s", host, service);
    auto addrinfos = getAddressInfo(host, service, SocketType.STREAM, ProtocolType.TCP);
    foreach(addrinfo; addrinfos) {
      try {
        if(verbose > 1) stderr.writefln("connect: %s", addrinfo);
        auto socket = new Socket(addrinfo);
        socket.connect(addrinfo.address);
        return socket;
      } catch(SocketException ex) {
        if(verbose > 1) stderr.writefln("connection failed (%s)", ex.msg);
        // try next
      }
    }
    throw new RConException("connection failure");
  }

  struct Packet {
    int id, type;
    const(char)[] content;
  }

  void send(Packet packet) {
    if(verbose > 2) stderr.writefln("send: %s", packet);

    int len = cast(int)(packet.content.length + 10);
    endpoint.write(len);
    endpoint.write(packet.id);
    endpoint.write(packet.type);
    endpoint.writeExact(packet.content.ptr, packet.content.length);
    endpoint.write('\0');
    endpoint.write('\0');
    endpoint.flush();
  }

  Packet recv() {
    typeof(return) packet;

    int len = void;
    endpoint.read(len);
    endpoint.read(packet.id);
    endpoint.read(packet.type);
    auto content = new char[](len - 10);
    endpoint.readExact(content.ptr, content.length);
    packet.content = content;
    endpoint.getc(); // '\0'
    endpoint.getc(); // '\0'

    if(verbose > 2) stderr.writefln("recv: %s", packet);
    return packet;
  }

public:
  enum defaultService = "27015";

  this(string host, string service) {
    auto socket = connect(host, service);
    endpoint = new EndianStream(new SocketStream(socket), Endian.littleEndian);
  }

  void login(string password) {
    if(verbose > 1) stderr.writeln("sending password to server");
    send(Packet(0xCAFE, SERVERDATA_AUTH, password));

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
    immutable seq = ++sequence;

    if(verbose > 1) stderr.writeln("sending command to server");
    send(Packet(seq, SERVERDATA_EXECCOMMAND, command));

    if(verbose > 1) stderr.writeln("receiving response for command");
    auto res = recv();

    if(res.id != seq || res.type != SERVERDATA_RESPONSE_VALUE) {
      throw new RConException("execution failure");
    }

    return assumeUnique(res.content);
  }

  class RConException : Exception {
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
