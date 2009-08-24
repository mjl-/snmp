Snmpclient: module {
	PATH:   con "/dis/lib/snmpclient.dis";

	dflag:  int;
	init:   fn();

	usage:  string;

	Snmpc: adt {
		version:	int;
		community:	string;
		timeout:	int;
		retries:	int;
		addr:		string;
		conn:	Sys->Connection;
		reqgen:		int;

		new:	fn(): ref Snmpc;
		setopt:	fn(s: self ref Snmpc, c: int, arg: Arg);
		init:	fn(s: self ref Snmpc): string;
		clone:	fn(s: self ref Snmpc): (ref Snmpc, string);
		get:	fn(s: self ref Snmpc, o: string): (string, ref Snmp->Val, string);
		getm:	fn(s: self ref Snmpc, l: list of string): (list of ref (string, ref Snmp->Val), string);
		set:	fn(s: self ref Snmpc, o: string, v: ref Snmp->Val): (string, ref Snmp->Val, string);
		setm:	fn(s: self ref Snmpc, p: list of ref (string, ref Snmp->Val)): (list of ref (string, ref Snmp->Val), string);
		next:	fn(s: self ref Snmpc, o: string): (string, ref Snmp->Val, string);
		nextbulk:	fn(s: self ref Snmpc, o: string, max: int): (list of ref (string, ref Snmp->Val), string);
		walk:	fn(s: self ref Snmpc, o: string): (list of ref (string, ref Snmp->Val), string);
	};

	walker:	fn(s: ref Snmpc, o: string): chan of (list of ref (string, ref Snmp->Val), string);
};
