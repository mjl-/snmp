implement SnmpWalk;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "snmp.m";
	snmp: Snmp;
	Val: import snmp;
include "snmpclient.m";
	snmpclient: Snmpclient;
	Snmpc: import snmpclient;

SnmpWalk: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	snmp = load Snmp Snmp->PATH;
	snmp->init();
	snmpclient = load Snmpclient Snmpclient->PATH;
	snmpclient->init();

	s := Snmpc.new();
	arg->init(args);
	arg->setusage(arg->progname()+" [-d] "+snmpclient->usage+" addr oid ...");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	snmp->dflag = dflag++;
		* =>	s.setopt(c, arg);
		}
	args = arg->argv();
	if(len args < 2)
		arg->usage();
	s.addr = hd args;
	args = tl args;

	b := bufio->fopen(sys->fildes(1), Bufio->OWRITE);

	err := s.init();
	if(err != nil)
		fail(err);
	for(; args != nil; args = tl args) {
		ch := snmpclient->walker(s, hd args);
		for(;;) {
			l: list of ref (string, ref Val);
			(l, err) = <-ch;
			if(l == nil && err == nil)
				break;
			if(err != nil)
				fail(err);
			for(; l != nil; l = tl l) {
				(o, v) := *hd l;
				if(b.puts(sprint("%-35s %s\n", o, v.text())) == Bufio->ERROR)
					fail(sprint("write: %r"));
			}
		}
	}
	if(b.flush() == Bufio->ERROR)
		fail(sprint("flush: %r"));
}

fail(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
	raise "fail:"+s;
}
