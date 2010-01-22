Snmp: module
{
	PATH:	con "/dis/lib/snmp.dis";

	dflag:	int;
	init:	fn();

	Snmpv1, Snmpv2c: con iota;

	# Val.Other.v
	VEnosuchobject,
	VEnosuchinstance,
	VEendofmibview:	con iota;
	valotherstr:	fn(i: int): string;

	# snmp/smi types
	Val: adt {
		pick {
		Int =>		i:	int;
		Bytes =>	b:	array of byte;
		Oid =>		o:	string;
		Ip4 =>		b:	array of byte;
		Counter =>	i:	big;
		Gauge =>	i:	big;
		Uint =>		i:	big;
		Ticks =>	i:	big;
		Opaque =>	o:	array of byte;
		Counter64 =>	i:	big;

		Null =>
		Other =>	v:	int;
		}

		parse:	fn(s: string): (ref Val, string);
		text:	fn(v: self ref Val): string;
	};

	Getrequest, Getnextrequest, Response, Setrequest: con iota;
	Getbulkrequest, Informrequest, Snmp2trap: con Setrequest+1+iota;

	ESnone,
	EStoobig,
	ESnosuchname,
	ESbadvalue,
	ESreadonly,
	ESgenerr,
	ESnoaccess,
	ESwrongtype,
	ESwronglength,
	ESwrongencoding,
	ESwrongvalue,
	ESnocreation,
	ESinconsistentvalue,
	ESresourceunvail,
	EScommitfailed,
	ESundofailed,
	ESauthorizationerror,
	ESnotwritable,
	ESinconsistentname:	con iota;
	errorstrs: array of string;

	Msg: adt {
		version:	int;
		community:	string;
		reqid,
		error,			# non-repeaters for bulk
		index:		int;	# max-repetitions for bulk
		pick {
		Get or
		Getnext =>
			oids:	list of string;
		Response or
		Set =>
			l:	list of ref (string, ref Val);
		Getbulk =>
			oids:	list of string;
		}

		parse:	fn(buf: array of byte): (ref Msg, string);
		read:	fn(fd: ref Sys->FD, timeout: int): (ref Msg, string);
		pack:	fn(m: self ref Msg): (array of byte, string);
		write:	fn(m: self ref Msg, fd: ref Sys->FD): string;
	};
};
