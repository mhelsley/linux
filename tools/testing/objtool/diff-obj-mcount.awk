BEGIN	{
		num_obj_files = 0;

		# Results from checking the first obj file
		first_obj_filename = "";
		first_has_reloc_flag = 0;
		first_num_sections = 0;
		first_total_section_size = 0;
		first_num_relocs = 0;
		first_num_syms = 0;
		first_content_lines = 0;

		# Set this to true to see all the
		# debug output.
		debug = 0;

		# Exit status -- NOTE: do not modify if success,
		# and only set to 1 if failure.
		rc = 0;
	}

BEGINFILE {	# Parser states
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

		if (num_obj_files == 0) {
			first_obj_filename = FILENAME;
		}
		num_obj_files++;
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
			total_section_size += section_size;
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

ENDFILE	{
		# Prepare for first diff
		if (num_obj_files == 2) {
			# Only save the the previous values once so we
			# always compare to first obj file
			first_has_reloc_flag = has_reloc_flag;
			first_num_sections = num_sections;
			first_total_section_size = total_section_size;
			first_num_relocs = num_relocs;
			first_num_syms = num_syms;
			first_content_lines = content_lines;
		}

		##
		# Check obj file mcount sections
		##
		if (FILENAME != "-") {
			prefix = FILENAME ": ";
		} else {
			prefix = "";
		}
		if (debug) print prefix "parser state:" parser;

		# The section is the most important thing
		if (num_sections < 1) {
			print prefix "Missing __mcount_loc section";
			exit(1);
		}
		if (num_sections > 1) {
			print prefix "More than one __mcount_loc section";
			exit(1);
		}
		if (content_lines < 1) {
			print prefix "Missing or empty __mcount_loc section";
			exit(1);
		}

		if (!has_reloc_flag) {
			print prefix "No relocations";
			exit(1);
		}
		if (num_relocs < 1) {
			print prefix "Missing relocations";
			exit(1);
		}

		# An __mcount_loc symbol is optional but multiple is an error
		#if (num_syms < 1) {
		#	print prefix "Missing __mcount_loc symbol";
		#	exit(1);
		#}
		if (num_syms > 1) {
			print prefix "More than one __mcount_loc symbol";
			exit(1);
		}

		if (parser < 1 || !(parser == 1 || parser == 4)) {
			print prefix "Unexpected objdump output final parsing state";
			exit(1);
		}

		if (num_obj_files > 1) {

		##
		# Diff checked mcount sections
		##

		# Indicate which files we are comparing
		suffix = "" #" : " first_obj_filename " <=> " FILENAME
		prefix = first_obj_filename " <=> " FILENAME ": "

		# We want to show all the differences rather than exit
		# at the first one found so we modify the exit status in
		# rc rather than exit immediately.

		# The section is the most important thing
		if (num_sections != first_num_sections) {
			print prefix "Difference in number of __mcount_loc sections (" first_num_sections " <=> " num_sections ")" suffix;
			rc = 1;
		}
		if (total_section_size != first_total_section_size) {
			print prefix "Difference __mcount_loc section sizes (" first_total_section_size " <=> " total_section_sizes ")" suffix;
			rc = 1;
		}
		if (content_lines != first_content_lines) {
			print prefix "Difference in __mcount_loc contents" suffix;
			rc = 1;
		}

		if (has_reloc_flag != first_has_reloc_flag) {
			print prefix "Difference in presence/absence of relocations" suffix;
			rc = 1;
		}
		if (num_relocs != first_num_relocs) {
			print prefix "Different numbers of mcount relocation entries (" first_num_relocs " <=> " num_num_relocs ")" suffix;
			rc = 1;
		}

		# An __mcount_loc symbol is optional but if we're
		# diffing output then a difference in presence/absence
		# is relevant.
		if (num_syms != first_num_syms) {
			print prefix "More than one __mcount_loc symbol" suffix;
			rc = 1;
		}

		# TODO compare mcount section contents?
		}
	}

END	{ exit(rc); }
