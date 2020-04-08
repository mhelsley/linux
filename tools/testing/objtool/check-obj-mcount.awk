BEGIN	{	# Parser states
		#  0 file header
		#  1 tables
		#  2 table name
		#  3 table column names
		#  4 table entry
		#  5 table entry 2

		parser = 0;
		table = "";
		has_reloc_flag = 0;
		num_sections = 0;
		num_relocs = 0;
		num_syms = 0;
		content_lines = 0;

		# Set this to true to see all the
		# debug output.
		debug = 0;
	}

# Debug output
(debug) && (parser == 0) { print "Parsing header" ; }
(debug) && (parser == 1) { print "Parsing table" table ; }
(debug) && (parser == 2) { print "Parsing table name " table ; }
(debug) && (parser == 3) { print "Parsing " table " table column names" ; }
(debug) && (parser == 4) { print "Parsing " table " table entry" ; }
(debug) && (parser == 5) { print "Parsing " table " table entry (line 2)" ; }

##
# Generic parser transitions
##
(parser > 0) && (table != "") && /^$/ {
		if (debug) print "End of " table " table";
		parser = 1;
		table = "";
		next; 
	}

/^$/ { parser = 1; table = ""; next; }

(parser == 1) && /^.*:$/ {
		parser = 2;
		if (debug) print "Determining table name";
	}

# Parse the file header
(parser == 0) && /^[^:]+:\s+file format .*$/ {
		if (debug) print "Matched file format line";
		next;
	}
(parser == 0) && /^architecture: [^,]+, flags 0x[0-9a-fA-F]+:$/ {
		if (debug) print "Matched arch and flags line";
		next;
	}
(parser == 0) && /^.*HAS_RELOC.*$/ {
		if (debug) print "Found HAS_RELOC";
		has_reloc_flag = 1;
		next;
	}

##
# Tables
##
# Section table
(parser == 2) && /^Sections:$/ {
		if (debug) print "Started parsing section table";
		parser = 3;
		table = "sections";
		next;
	}
(parser == 3) && (table == "sections") && /^Idx\s+Name\s+Size\s+VMA\s+LMA\s+File off\s+Algn\s*$/ {
		if (debug) print "Found header of section table";
		parser = 4;
		next;
	}
(parser == 4) && (table == "sections") && /^\s*[0-9]+\s+__mcount_loc\s+[0-9a-fA-F]+\s+.*$/ {
		if (debug) print "Found __mcount_loc section table entry";
		section_size = strtonum("0x" $3);
		if (section_size < 4) {
			if (debug) print "Empty __mcount_loc section";
			exit(1);
		} else {
			if (debug) print "__mcount_loc section size is " section_size " bytes";
		}
		num_sections++;
		parser = 5;
		next;
	}
(parser == 4) && (table == "sections") && /^\s*[0-9]+\s+[^[:space:]]+\s+[0-9a-fA-F]+\s+.*$/ {
		if (debug) print "Skipping section table entry";
		parser = 5;
		next;
	}
(parser == 5) && (table == "sections") {
		if (debug) print "Skipping section table entry flags";
		parser = 4;
		next;
	}
((parser == 2) || ((parser == 4) && (table == "sections"))) && /^SYMBOL TABLE:$/ {
		if (debug) print "Found symbol table start";
		table = "symbol";
		parser = 4;
		next;
	}
(parser == 4) && (table == "symbol") && /^[0-9a-fA-F]+\s+.*\s+__mcount_loc\s+[0-9a-fA-F]+\s+__mcount_loc$/ {
		if (debug) print "Found __mcount_loc symbol";
		num_syms++;
		next;
	}
(parser == 4) && (table == "symbol") && /^[0-9a-fA-F]+\s+.*\s+\S+\s+[0-9a-fA-F]+\s+\S+$/{
		if (debug) print "Skipping irrelevant symbol";
		next;
	}
(parser == 2) && /^RELOCATION RECORDS FOR \[__mcount_loc\]:$/ {
		if (debug) print "Found __mcount_loc relocation table";
		table = "relocation";
		parser = 3;
		next;
	}
(parser == 3) && (table == "relocation") && /^\s*OFFSET\s+TYPE\s+VALUE\s*$/ {
		if (debug) print "Found relocation table column names";
		parser = 4;
		next;
	}
(parser == 4) && (table == "relocation") && /^[0-9]+\s+[^[:space:]]+\s+\S+$/ {
		if (debug) print "Found __mcount_loc relocation entry";
		num_relocs++;
		next;
	}
(parser == 2) && (table == "") && /^Contents of section __mcount_loc:$/ {
		if (debug) print "Found __mcount_loc section contents";
		table = "__mcount_loc";
		content_lines = 0;
		parser = 4;
		next;
	}
(parser == 4) && (table == "__mcount_loc") && /^.+$/ {
		content_lines++;
		next;
	}

##
# Last parser rule
##
/^.*$/ {
		if (debug) print "ignored: \"" $0 "\"";
		next;
	}

END	{
		if (debug) print "Parser state:" parser;

		# The section is the most important thing
		if (num_sections < 1) {
			print "Missing __mcount_loc section";
			exit(1);
		}
		if (num_sections > 1) {
			print "More than one __mcount_loc section";
			exit(1);
		}
		if (content_lines < 1) {
			print "Missing or empty __mcount_loc section";
			exit(1);
		}

		if (!has_reloc_flag) {
			print "No relocations";
			exit(1);
		}
		if (num_relocs < 1) {
			print "Missing relocations";
			exit(1);
		}

		# An __mcount_loc symbol is optional but multiple is an error
		#if (num_syms < 1) {
		#	print "Missing __mcount_loc symbol";
		#	exit(1);
		#}
		if (num_syms > 1) {
			print "More than one __mcount_loc symbol";
			exit(1);
		}

		if (parser < 1 || !(parser == 1 || parser == 4)) {
			print "Unexpected objdump output final parsing state";
			exit(1);
		}
		exit(0);
	}
