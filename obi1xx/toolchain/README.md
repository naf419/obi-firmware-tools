haha, theres no toolchain for this: these aren't running linux.

however, a dissassembler thats pretty close can be found here (if yahoo still exists): http://groups.yahoo.com/group/mipsx_src/files/PAP2/mipsxdis.zip

important note on that dissessembler, the jspci instructions are decoded incorrectly: the actual jumps are never relative, they are all positive offsets (with the resulting address truncated to 20 lsbs)
