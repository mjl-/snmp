implement Snmpclient;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "arg.m";
include "dial.m";
	dial: Dial;
include "string.m";
	str: String;
include "lists.m";
	lists: Lists;
include "asn1.m";
	asn1: ASN1;
	Elem, Tag, Value, Oid: import asn1;
include "snmp.m";
	snmp: Snmp;
	Val, Msg: import snmp;
include "snmpclient.m";

usage = "[-v 1|2c] [-c community] [-t timeout] [-r retries]";

init()
{
	sys = load Sys Sys->PATH;
	dial = load Dial Dial->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	asn1 = load ASN1 ASN1->PATH;
	asn1->init();
	snmp = load Snmp Snmp->PATH;
	snmp->init();
}

transact(s: ref Snmpc, tm: ref Msg): (ref Msg, string)
{
	n := s.retries;
Send:
	for(;;) {
		err := tm.write(s.conn.dfd);
		if(err != nil)
			return (nil, err);
		rm: ref Msg;
	Recv:
		for(;;) {
			(rm, err) = Msg.read(s.conn.dfd, s.timeout);
			if(err == "timeout" && --n > 0)
				continue Send;
			if(err == nil) {
				if(rm.reqid < tm.reqid)
					continue Recv;  # could be old message?
				if(rm.reqid > tm.reqid)
					err = sprint("request id mismatch, expected %d, saw %d", tm.reqid, rm.reqid);
				# xxx
				#if(len r.l != len req.oids)
				#	err = sprint("response body mismatch, expected %d pairs, saw %d pairs", len req.oids, len r.l);
			}
			return (rm, err);
		}
	}
}

zerocon: Sys->Connection;
Snmpc.new(): ref Snmpc
{
	return ref Snmpc (snmp->Snmpv2c, "public", 2000, 3, "udp!localhost!snmp", zerocon, 1);
}

Snmpc.setopt(s: self ref Snmpc, c: int, arg: Arg)
{
	case c {
	'v' =>
		case arg->arg() {
		"1" =>	s.version = snmp->Snmpv1;
		"2c" =>	s.version = snmp->Snmpv2c;
		* =>	arg->usage();
		}
	'c' =>	s.community = arg->arg();
	't' =>	s.timeout = int arg->arg();
	'r' =>	s.retries = int arg->arg();
	* =>	arg->usage();
	}
}

Snmpc.init(s: self ref Snmpc): string
{
	addr := dial->netmkaddr(s.addr, "udp", "snmp");
	c := dial->dial(addr, nil);
	if(c == nil)
		return sprint("dial %q: %r", addr);
	s.conn = *c;
	return nil;
}

Snmpc.clone(s: self ref Snmpc): (ref Snmpc, string)
{
	s = ref *s;
	s.reqgen = 0;
	err := s.init();
	return (s, err);
}

Snmpc.get(s: self ref Snmpc, o: string): (string, ref Val, string)
{
	(l, err) := s.getm(o::nil);
	if(err == nil)
		(no, nv) := *hd l;
	if(err == nil)
		pick v := nv {
		Other =>	err = snmp->valotherstr(v.v);
		}
	return (no, nv, err);
}

Snmpc.getm(s: self ref Snmpc, l: list of string): (list of ref (string, ref Val), string)
{
	tm := ref Msg.Get (s.version, s.community, s.reqgen++, 0, 0, l);
	(rm, err) := transact(s, tm);
	if(err != nil)
		return (nil, err);

	pick r := rm {
	Response =>
		return (r.l, nil);
	* =>	return (nil, sprint("bad type of response message"));
	}
}

Snmpc.set(s: self ref Snmpc, o: string, v: ref Val): (string, ref Val, string)
{
	(l, err) := s.setm(ref (o, v)::nil);
	if(err == nil)
		(no, nv) := *hd l;
	if(err == nil)
		pick vv := nv {
		Other =>	err = snmp->valotherstr(vv.v);
		}
	return (no, nv, err);
}

Snmpc.setm(s: self ref Snmpc, p: list of ref (string, ref Val)): (list of ref (string, ref Val), string)
{
	tm := ref Msg.Set (s.version, s.community, s.reqgen++, 0, 0, p);
	(rm, err) := transact(s, tm);
	if(err != nil)
		return (nil, err);

	pick r := rm {
	Response =>
		return (r.l, nil);
	* =>	return (nil, sprint("bad type of response message"));
	}
}

Snmpc.next(s: self ref Snmpc, o: string): (string, ref Val, string)
{
	tm := ref Msg.Getnext (s.version, s.community, s.reqgen++, 0, 0, list of {o});
	(rm, err) := transact(s, tm);
	if(err != nil)
		return (nil, nil, err);

	pick r := rm {
	Response =>
		if(len r.l != 0)
			(no, nv) := *hd r.l;
		if(nv != nil)
			pick vv := nv {
			Other =>
				if(vv.v == snmp->VEendofmibview) {
					no = nil;
					nv = nil;
				}
			}
		return (no, nv, nil);
	* =>	return (nil, nil, sprint("bad type of response message"));
	}
}

Snmpc.nextbulk(s: self ref Snmpc, o: string, max: int): (list of ref (string, ref Val), string)
{
	if(s.version != snmp->Snmpv2c)
		return (nil, sprint("nextbulk only supported on snmpv2c"));
	if(max < 0)
		max = 64*1024;  # could limit this, or check for error "toobig" and try again with lower value
	tm := ref Msg.Getbulk (s.version, s.community, s.reqgen++, 0, max, list of {o});
	(rm, err) := transact(s, tm);
	if(err != nil)
		return (nil, err);

	pick r := rm {
	Response =>
		return (r.l, nil);
	* =>	return (nil, sprint("bad type of response message"));
	}
}

Snmpc.walk(s: self ref Snmpc, o: string): (list of ref (string, ref Val), string)
{
	if(s.version == snmp->Snmpv2c)
		return s.nextbulk(o, -1);

	(no, nv, err) := s.next(o);
	if(err == nil && no != nil)
		l := ref (no, nv)::nil;
	return (l, err);
}

walker0(s: ref Snmpc, o: string, c: chan of (list of ref (string, ref Val), string))
{
	orig := o;
	for(;;) {
		(l, err) := s.walk(o);
		stop := 0;
		if(l != nil && err == nil) {
		Skip:
			for(l = lists->reverse(l); l != nil ; l = tl l)
				if(str->prefix(orig, (hd l).t0))
					pick vv := (hd l).t1 {
					Other =>
						if(vv.v != snmp->VEendofmibview)
							break Skip;
						stop = 1;
					* =>
						break Skip;
					}
				else
					stop = 1;
			l = lists->reverse(l);
		}
		c <-= (l, err);
		if(err != nil || l == nil)
			break;
		if(stop) {
			c <-= (nil, nil);
			break;
		}
		o = (hd lists->reverse(l)).t0;
	}
}

walker(s: ref Snmpc, o: string): chan of (list of ref (string, ref Val), string)
{
	c := chan[1] of (list of ref (string, ref Val), string);
	spawn walker0(s, o, c);
	return c;
}

say(s: string)
{
	if(dflag)
		sys->fprint(sys->fildes(2), "%s\n", s);
}
