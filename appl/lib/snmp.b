implement Snmp;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "arg.m";
include "string.m";
	str: String;
include "lists.m";
	lists: Lists;
include "ip.m";
	ip: IP;
	IPaddr: import ip;
include "asn1.m";
	asn1: ASN1;
	Elem, Tag, Value, Oid: import asn1;
include "snmp.m";

errorstrs = array[] of {
"",
"too big",
"no such name",
"bad value",
"read only",
"generic error",
"no access",
"wrong type",
"wrong length",
"wrong encoding",
"wrong value",
"no creation",
"inconsistent value",
"resource unavailable",
"commit failed",
"undo failed",
"authorization error",
"not writable",
"inconsistent name",
};

Aip4,
Acounter32,
Aunsigned32,
Atimeticks,
Aopaque:	con iota;
Acounter64:	con Aopaque+2;

init()
{
	sys = load Sys Sys->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	ip = load IP IP->PATH;
	ip->init();
	asn1 = load ASN1 ASN1->PATH;
	asn1->init();
}

oidparse(s: string): (ref Oid, string)
{
	{
		checkoid(s);
	} exception e {
	"parse:*" =>
		return (nil, e[len "parse:":]);
	}
	l := sys->tokenize(s, ".").t1;
	if(len l > 128)
		return (nil, "too many numbers in oid, max is 128");
	o := ref Oid (array[len l] of int);
	i := 0;
	for(; l != nil; l = tl l) {
		(v, rem) := str->toint(hd l, 10);
		if(rem != nil)
			return (nil, "bad number in oid");
		o.nums[i++] = v;
	}
	return (o, nil);
}

parseint(s: string): int
{
	(i, rem) := str->toint(s, 10);
	if(rem != nil)
		raise "parse:bad int";
	return i;
}

parseuint(s: string): big
{
	(i, rem) := str->tobig(s, 10);
	if(rem != nil)
		raise "parse:bad unsigned int";
	if(i < big 0 || i > big 2**32)
		raise "parse:value out of range for unsigned int";
	return i;
}

parsebig(s: string): big
{
	(i, rem) := str->tobig(s, 10);
	if(rem != nil)
		raise "parse:bad big";
	return i;
}

hexc(c: int): int
{
	if(c >= '0' && c <= '9')
		return c-'0';
	if(c >= 'a' && c <= 'f')
		return c-'a'+10;
	if(c >= 'A' && c <= 'F')
		return c-'A'+10;
	raise "parse:bad hex";
}

parsehex(s: string): array of byte
{
	if(len s % 2 != 0)
		raise "parse:bad hex, odd number of bytes";
	d := array[len s/2] of byte;
	o := 0;
	for(i := 0; i < len s; i += 2)
		d[o++] = byte ((hexc(s[i])<<4)|hexc(s[i+1]));
	return d;
}

checkoid(s: string)
{
	for(i := 0; i < len s; i++)
		if(!str->in(s[i], "0-9.-"))
			raise "parse:bad oid, has non-digit,non-dot";
	for(i = 0; i < len s-1; i++)
		if(s[i] == '.' && s[i+1] == '.')
			raise "parse:bad oid, missing number";
	if(str->prefix(".", s))
		raise "parse:bad oid, leading .";
	if(s != nil && s[len s-1] == '.')
		raise "parse:bad oid, trailing .";
}

parseoid(s: string): string
{
	checkoid(s);
	return s;
}

parseip(s: string): array of byte
{
	(ok, i) := IPaddr.parse(s);
	if(ok < 0)
		raise "parse:bad ip";
	if(!i.isv4())
		raise "parse:not ip4 address";
	return i.v4();
}

valuestrs := array[] of {
tagof Val.Int =>	"i",
tagof Val.Bytes =>	"s",  # and S in case of ascii
tagof Val.Oid =>	"oid",
tagof Val.Ip4 =>	"ip",
tagof Val.Counter =>	"c",
tagof Val.Gauge =>	"g",
tagof Val.Uint =>	"u",
tagof Val.Ticks =>	"t",
tagof Val.Opaque =>	"opaque",
tagof Val.Counter64 =>	"C",

tagof Val.Null =>	"null",
tagof Val.Other =>	"other",
};

valotherstr(i: int): string
{
	case i {
	VEnosuchobject =>	return "no such object";
	VEnosuchinstance =>	return "no such instance";
	VEendofmibview =>	return "end of mib view";
	* =>
		return sprint("unknown %d", i);
	}
}

Val.parse(s: string): (ref Val, string)
{
	(t, r) := str->splitstrl(s, ":");
	if(r == nil)
		return (nil, sprint("missing type (separator)"));
	r = r[1:];
	v: ref Val;
	{
		case t {
		"i" =>	v = ref Val.Int (parseint(r));
		"s" =>	v = ref Val.Bytes (parsehex(r));
		"S" =>	v = ref Val.Bytes (array of byte r);
		"oid" =>	v = ref Val.Oid (parseoid(r));
		"ip" =>	v = ref Val.Ip4 (parseip(r));
		"c" =>	v = ref Val.Counter (parseuint(r));
		"g" =>	v = ref Val.Gauge (parseuint(r));
		"u" =>	v = ref Val.Uint (parseuint(r));
		"t" =>	v = ref Val.Ticks (parseuint(r));
		"opaque" =>	v = ref Val.Opaque (parsehex(r));
		"C" =>	v = ref Val.Counter64 (parsebig(r));
		* =>
			return (nil, sprint("unknown type %#q", t));
		}
	} exception e {
	"parse:*" =>
		return (nil, e[len "parse:":]);
	}
	return (v, nil);
}

Val.text(vv: self ref Val): string
{
	s: string;
	pick v := vv {
	Int =>          s = string v.i;
	Bytes =>        if(isascii(v.b))
				return sprint("S:%q", string v.b);
			s = hex(v.b);
	Oid =>          s = v.o;
	Ip4 =>          s = IPaddr.newv4(v.b).text();
	Counter =>      s = string v.i;
	Gauge =>        s = string v.i;
	Uint =>		s = string v.i;
	Ticks =>        s = string v.i;
	Opaque =>       s = hex(v.o);
	Counter64 =>	s = string v.i;

	Null =>		s = "";
	Other =>	s = string v.v;
	}
	return valuestrs[tagof vv]+":"+s;
}


elemint(v: int): ref Elem
{
	return ref Elem (Tag (asn1->Universal, asn1->INTEGER, 0), ref Value.Int (v));
}

elemstr(s: string): ref Elem
{
	return ref Elem (Tag (asn1->Universal, asn1->OCTET_STRING, 0), ref Value.Octets (array of byte s));
}

elembytes(d: array of byte): ref Elem
{
	return ref Elem (Tag (asn1->Universal, asn1->OCTET_STRING, 0), ref Value.Octets (d));
}

elemseq(l: list of ref Elem): ref Elem
{
	return ref Elem (Tag (asn1->Universal, asn1->SEQUENCE, 0), ref Value.Seq (l));
}

elemoid(oid: ref Oid): ref Elem
{
	return ref Elem (Tag (asn1->Universal, asn1->OBJECT_ID, 0), ref Value.ObjId (oid));
}

elemnull(): ref Elem
{
	return ref Elem (Tag (asn1->Universal, asn1->NULL, 0), nil);
}


getseq(e: ref Elem): list of ref Elem
{
	if(e.tag.class == asn1->Universal && e.tag.num == asn1->SEQUENCE)
		pick v := e.val {
		Seq =>	return v.l;
		}
	raise "msgparse:expected sequence (universal), saw "+e.tostring();
}

getint(e: ref Elem): int
{
	if(e.tag.class == asn1->Universal && e.tag.num == asn1->INTEGER)
		pick v := e.val {
		Int =>	return v.v;
		}
	raise "msgparse:expected integer (universal), saw "+e.tostring();
}

getstr(e: ref Elem): string
{
	if(e.tag.class == asn1->Universal && e.tag.num == asn1->OCTET_STRING)
		pick v := e.val {
		Octets =>	return string v.bytes;
		}
	raise "msgparse:expected (octet) string (universal), saw "+e.tostring();
}

getcontext(e: ref Elem, num: int): ref Value
{
	if(e.tag.class == asn1->Context && e.tag.num == num)
		return e.val;
	raise "msgparse:expected (octet) string (universal), saw "+e.tostring();
}

getoid(e: ref Elem): ref Oid
{
	if(e.tag.class == asn1->Universal && e.tag.num == asn1->OBJECT_ID)
		pick v := e.val {
		ObjId =>	return v.id;
		}
	raise "msgparse:expected object identifier (universal), saw "+e.tostring();
}

checklen(have, want: int)
{
	if(have != want)
		raise sprint("msgparse:bad length, expected %d, saw %d", want, have);
}


valgetoctets(vv: ref Value): array of byte
{
	pick v := vv {
	Octets =>	return v.bytes;
	}
	raise "msgparse:expected octet string, saw "+vv.tostring();
}

valgetint(vv: ref Value): int
{
	pick v := vv {
	Int =>	return v.v;
	Octets =>	return int gint(v.bytes);
	}
	raise sprint("msgparse:expected int, saw %s (tag %d)", vv.tostring(), tagof vv);
}

valgetuint(vv: ref Value): big
{
	pick v := vv {
	Int =>	return big v.v;
	Octets =>
		r := gint(v.bytes);
		if(r < big 0 || r > big 2**32)
			raise sprint("msgparse:unsigned int out of range, %bd", r);
		return r;
	}
	raise sprint("msgparse:expected int, saw %s (tag %d)", vv.tostring(), tagof vv);
}

valgetbigint(vv: ref Value): big
{
	pick v := vv {
	BigInt =>	return g64(v.bytes);
	}
	raise "msgparse:expected int, saw "+vv.tostring();
}

elem2val(e: ref Elem): (ref Val, string)
{
	r: ref Val;
	case e.tag.class {
	asn1->Universal =>
		pick v := e.val {
		Bool or
		Int =>		r = ref Val.Int (v.v);
		Octets => 	r = ref Val.Bytes (v.bytes);
		ObjId => 	r = ref Val.Oid (v.id.tostring());
		Null =>		r = ref Val.Null ();
		* =>	return (nil, sprint("unexpected universal value %d", e.tag.num));
		}
	asn1->Application =>
		case e.tag.num {
		Aip4 =>		r = ref Val.Ip4 (valgetoctets(e.val));
		Acounter32 =>	r = ref Val.Counter (valgetuint(e.val));
		Aunsigned32 =>	r = ref Val.Uint (valgetuint(e.val));
		Atimeticks =>	r = ref Val.Ticks (valgetuint(e.val));
		Aopaque =>	r = ref Val.Opaque (valgetoctets(e.val));
		Acounter64 =>	r = ref Val.Counter64 (valgetbigint(e.val));
		* =>	return (nil, sprint("unexpected application value %d", e.tag.num));
		}
	* =>
		return (nil, sprint("unexpected value tag class %d", e.tag.class));
	}
		
	return (r, nil);
}

val2elem(vv: ref Val): ref Elem
{
	pick v := vv {
	Int =>		return elemint(v.i);
	Bytes =>	return elembytes(v.b);
	Oid =>		return elemoid(oidparse(v.o).t0);
	Ip4 =>          return ref Elem (Tag (asn1->Context, Aip4, 0), ref Value.Octets (v.b));
	Counter =>      return ref Elem (Tag (asn1->Context, Acounter32, 0), ref Value.BigInt (mku32(v.i)));
	Gauge or
	Uint =>         return ref Elem (Tag (asn1->Context, Aunsigned32, 0), ref Value.BigInt (mku32(v.i)));
	Ticks =>        return ref Elem (Tag (asn1->Context, Atimeticks, 0), ref Value.BigInt (mku32(v.i)));
	Opaque =>       return ref Elem (Tag (asn1->Context, Aopaque, 0), ref Value.Octets (v.o));
	Counter64 =>   
		d := array[8] of byte;
		p64(d, v.i);
		return ref Elem (Tag (asn1->Context, Acounter64, 0), ref Value.BigInt (d));

	Null =>		return ref Elem (Tag (asn1->Universal, asn1->NULL, 0), ref Value.Null (-1));
	Other =>	return ref Elem (Tag (asn1->Context, v.v, 0), ref Value.Int (v.v));
	* =>	raise "missing case";
	}
}

timeread(fd: ref Sys->FD, buf: array of byte, n, timeout: int): int
{
	tpid := -1;
	tc := chan of int;
	if(timeout) {
		spawn timer(timeout, tc);
		tpid = <-tc;
	}
	spawn reader(fd, buf, n, rc := chan of int);
	rpid := <-rc;
	alt {
	nn := <-rc =>
		if(tpid >= 0)
			kill(tpid);
		return nn;
	<-tc =>
		kill(rpid);
		sys->werrstr("timeout");
		return -1;
	}
}

timer(n: int, c: chan of int)
{
	c <-= sys->pctl(0, nil);
	sys->sleep(n);
	c <-= 1;
}

reader(fd: ref Sys->FD, buf: array of byte, n: int, c: chan of int)
{
	c <-= sys->pctl(0, nil);
	c <-= sys->read(fd, buf, n);
}


# xxx for now only parses Response messages
Msg.parse(buf: array of byte): (ref Msg, string)
{
	(err, resp) := asn1->decode(buf);
	if(err != nil)
		return (nil, "decoding response: "+err);

	exc: con "msgparse";
	act := "message";
	{
		seq := getseq(resp);
		checklen(len seq, 3);
		version := getint(hd seq);
		community := getstr(hd tl seq);
		pduval := getcontext(hd tl tl seq, Response);
		act = "message pdu";
		pdubuf := valgetoctets(pduval);
		pdu: list of ref Elem;
		(err, pdu) = asn1->decode_seq(pdubuf);
		if(err != nil)
			raise "msgparse:"+err;
		checklen(len pdu, 4);
		reqid := getint(hd pdu);
		error := getint(hd tl pdu);
		index := getint(hd tl tl pdu);
		rargs := getseq(hd tl tl tl pdu);
		act = "message pdu oid/values";

		if(error != ESnone) {
			errmsg := "unknown error";
			if(error >= 0 || error < len errorstrs)
				errmsg = errorstrs[error];
			return (nil, sprint("request failed, index %d, error %d (%s)", index, error, errmsg));
		}

		r: list of ref (string, ref Val);
		act = "message pdu oid/value pair";
		for(; rargs != nil; rargs = tl rargs) {
			pair := getseq(hd rargs);
			if(len pair == 1)
				break;  # this indicates end of mib on samsung printer
			checklen(len pair, 2);
			oid := getoid(hd pair);
			ve := hd tl pair;
			v: ref Val;
			case ve.tag.class {
			asn1->Universal or
			asn1->Application =>
				(v, err) = elem2val(ve);
				if(err != nil)
					return (nil, err);
			asn1->Context =>
				case ve.tag.num {
				VEnosuchobject or
				VEnosuchinstance or
				VEendofmibview =>
					v = ref Val.Other (ve.tag.num);
				* =>
					return (nil, sprint("unexpected value error %d", ve.tag.num));
				}
			* =>
				return (nil, sprint("unexpected tag class %d", ve.tag.class));
			}
			r = ref (oid.tostring(), v)::r;
		}

		m := ref Msg.Response (version, community, reqid, error, index, lists->reverse(r));
		return (m, nil);
	}
	exception e {
	exc+":*" =>
		return (nil, sprint("parsing %s: %s", act, e[len exc+1:]));
	}
}

Msg.read(fd: ref Sys->FD, timeout: int): (ref Msg, string)
{
	buf := array[64*1024] of byte;
	n := timeread(fd, buf, len buf, timeout);
	if(n < 0)
		return (nil, sprint("%r"));
	return Msg.parse(buf[:n]);
}

msgtagtypes := array[] of {
tagof Msg.Get =>	0,
tagof Msg.Getnext =>	1,
tagof Msg.Response =>	2,
tagof Msg.Set =>	3,
tagof Msg.Getbulk =>	5,
};
Msg.pack(mm: self ref Msg): (array of byte, string)
{
	# make l the reversed list for in the message
	l: list of ref (string, ref Val);
	pick m := mm {
	Get or
	Getnext =>
		for(o := m.oids; o != nil; o = tl o)
			l = ref (hd o, ref Val.Null ())::l;
	Response or
	Set =>
		l = lists->reverse(m.l);
	Getbulk =>
		for(o := m.oids; o != nil; o = tl o)
			l = ref (hd o, ref Val.Null ())::l;
	}

	# l is reversed, args will be in desired order
	args: list of ref Elem;
	for(; l != nil; l = tl l) {
		(oidstr, val) := *hd l;
		(oid, err) := oidparse(oidstr);
		if(err != nil)
			return (nil, err);
		if(val == nil)
			v := elemnull();
		else
			v = val2elem(val);
		arg := elemseq(elemoid(oid)::v::nil);
		args = arg::args;
	}

	pdu := ref Elem (Tag (asn1->Context, msgtagtypes[tagof mm], 0), ref Value.Seq (list of {
		elemint(mm.reqid),
		elemint(mm.error),
		elemint(mm.index),
		elemseq(args),
	}));
	req := elemseq(elemint(mm.version)::elemstr(mm.community)::pdu::nil);
	(err, buf) := asn1->encode(req);
	return (buf, err);
}

Msg.write(m: self ref Msg, fd: ref Sys->FD): string
{
	(buf, err) := m.pack();
	if(len buf > 64*1024)
		return sprint("request too large");
	if(err == nil && sys->write(fd, buf, len buf) != len buf)
		err = sprint("writing request: %r");
	return err;
}


isascii(d: array of byte): int
{
	for(i := 0; i < len d; i++)
		if(d[i] == byte 0 || d[i] > byte 127)
			return 0;
	return 1;
}

g64(d: array of byte): big
{
	v := big 0;
	o := 0;
	v |= big d[o++]<<56;
	v |= big d[o++]<<48;
	v |= big d[o++]<<40;
	v |= big d[o++]<<32;
	v |= big d[o++]<<24;
	v |= big d[o++]<<16;
	v |= big d[o++]<<8;
	v |= big d[o++]<<0;
	return v;
}

gint(d: array of byte): big
{
	v := big 0;
	for(i := 0; i < len d; i++)
		v  = v<<8 | big d[i];
	return v;
}

p64(d: array of byte, v: big)
{
	o := 0;
	d[o++] = byte (v>>56);
	d[o++] = byte (v>>48);
	d[o++] = byte (v>>40);
	d[o++] = byte (v>>32);
	d[o++] = byte (v>>24);
	d[o++] = byte (v>>16);
	d[o++] = byte (v>>8);
	d[o++] = byte (v>>0);
}

mku32(v: big): array of byte
{
	d := array[4] of byte;
	o := 0;
	d[o++] = byte (v>>24);
	d[o++] = byte (v>>16);
	d[o++] = byte (v>>8);
	d[o++] = byte (v>>0);
	return d;
}

hex(d: array of byte): string
{
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint("%02x", int d[i]);
	return s;
}

kill(pid: int)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	sys->fprint(fd, "kill");
}

say(s: string)
{
	if(dflag)
		sys->fprint(sys->fildes(2), "%s\n", s);
}
