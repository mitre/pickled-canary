
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mitre.pickledcanary.assembler.sleigh.symbol.AssemblyNumericTerminal;
import org.mitre.pickledcanary.search.SavedDataAddresses;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;

public class MipsBePickledCanaryTest extends PickledCanaryTest {

	@Override
	protected String getCompileInfoRaw() {
		return ",\"compile_info\":[{\"compiled_using_binary\":[{\"path\":[\"unknown\"],\"compiled_at_address\":[\"01006420\"],\"md5\":[\"unknown\"]}],\"language_id\":[\"MIPS:BE:32:default\"]}],\"pattern_metadata\":{}}";
	}

	private static final String CVE_2019_3822 =
			"; MIPS CVE-2019-3822\n"
			+ "\n"
            + "; This tests for code prior to the fix at:\n"
            + "; https://github.com/curl/curl/commit/50c9484278c63b958655a717844f0721263939cc\n"
            + "\n"
            + "; the condition \"if (size < (0x400 - ntresplen))\" is vulnerable to an integer overflow\n"
            + "; specifically if ntresplen is greater than 0x400\n"
            + "\n"
            + "; libcurl.so.4.3.0_5.50(ABEL.2)C0.zip.fae4f4bf510a453a978c31aadde1e961b54d2834d509f3c77aa1493fcf7b3c4b\n"
            + "; 0x00040a90\n"
            + "\n"
            + "; lw Q1, *\n"
            + "; li Q2, 0x400\n"
            + "; subu Q2, Q2, Q1\n"
            + "; sltu Q2, *, Q2\n"
            + "; bne Q2, zero, *\n"
            + "\n"
            + "; load value into ntresplen (Q1)\n"
            + "lw `Q1/.*/,`,0xfc(`*/.*/,`)\n"
            + "\r\n"
            + "; load 0x400 into Q2\n"
            + "li `Q2/.*/,`,0x400\n"
            + "\n"
            + "; subtract ntresplen from 0x400 and place difference in Q2\n"
            + "subu `Q2`,`Q2`,`Q1`\n"
            + "\n"
            + "; check if size < Q2\n"
            + "sltu `Q2`,`*`,`Q2`\n"
            + "bne `Q2`,zero,`*`";
	// TODO: check
	private static final String stepsForCVE_2019_3822 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,31,0,0]}],\"value\":[140,0,0,252]}],\"mask\":[252,0,255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,31,0,0]}],\"value\":[36,0,4,0]}],\"mask\":[255,224,255,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,248,0]},{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[3,224,0,0]},{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,31,0,0]}],\"value\":[0,0,0,35]}],\"mask\":[252,0,7,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,248,0]},{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,31,0,0]}],\"value\":[0,0,0,43]}],\"mask\":[252,0,7,255]}],\"type\":\"LOOKUP\"},{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[3,224,0,0]}],\"value\":[20,0,0,0]}],\"mask\":[252,31,0,0]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForCVE_2019_3822 = "{\"t4\":[{\"value\":[12],\"mask\":[31]}],\"t5\":[{\"value\":[13],\"mask\":[31]}],\"t6\":[{\"value\":[14],\"mask\":[31]}],\"t7\":[{\"value\":[15],\"mask\":[31]}],\"t8\":[{\"value\":[24],\"mask\":[31]}],\"t9\":[{\"value\":[25],\"mask\":[31]}],\"zero\":[{\"value\":[0],\"mask\":[31]}],\"s0\":[{\"value\":[16],\"mask\":[31]}],\"sp\":[{\"value\":[29],\"mask\":[31]}],\"s1\":[{\"value\":[17],\"mask\":[31]}],\"s2\":[{\"value\":[18],\"mask\":[31]}],\"s3\":[{\"value\":[19],\"mask\":[31]}],\"s4\":[{\"value\":[20],\"mask\":[31]}],\"s5\":[{\"value\":[21],\"mask\":[31]}],\"s6\":[{\"value\":[22],\"mask\":[31]}],\"s7\":[{\"value\":[23],\"mask\":[31]}],\"k0\":[{\"value\":[26],\"mask\":[31]}],\"s8\":[{\"value\":[30],\"mask\":[31]}],\"k1\":[{\"value\":[27],\"mask\":[31]}],\"gp\":[{\"value\":[28],\"mask\":[31]}],\"a0\":[{\"value\":[4],\"mask\":[31]}],\"ra\":[{\"value\":[31],\"mask\":[31]}],\"a1\":[{\"value\":[5],\"mask\":[31]}],\"a2\":[{\"value\":[6],\"mask\":[31]}],\"a3\":[{\"value\":[7],\"mask\":[31]}],\"at\":[{\"value\":[1],\"mask\":[31]}],\"v0\":[{\"value\":[2],\"mask\":[31]}],\"v1\":[{\"value\":[3],\"mask\":[31]}],\"t0\":[{\"value\":[8],\"mask\":[31]}],\"t1\":[{\"value\":[9],\"mask\":[31]}],\"t2\":[{\"value\":[10],\"mask\":[31]}],\"t3\":[{\"value\":[11],\"mask\":[31]}]}";

	private static final String branchPattern = "bne v0,zero, `*`";
	private static final String stepsForBranchPattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[20,64,0,0]}],\"mask\":[255,255,0,0]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForBranchPattern = "";

	private static final String multipleNumericQs = "pul.ps f0,`Q1/f[12]`,`Q2/f[12]`";
	private static final String stepsForMultipleNumericQs = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"var_id\":\"Q1\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,0,248,0]},{\"var_id\":\"Q2\",\"type\":\"Field\",\"table_id\":0,\"mask\":[0,31,0,0]}],\"value\":[70,192,0,46]}],\"mask\":[255,224,7,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForMultipleNumericQs = "{\"f1\":[{\"value\":[1],\"mask\":[31]}],\"f2\":[{\"value\":[2],\"mask\":[31]}]}";

	private static final String labelPattern =
			"lw a0,0x108(s2)     \n" 
			+ "beq a0,zero,`:foo`\n"
            + "`ANY_BYTES{0,40}`                                      \n"
            + "`foo:`                                                 \n"
            + "lw a0,0x10c(s2)                                        \n";
    private static final String misalignedLabelPattern =
    		"lw a0,0x108(s2)     \n"
            + "beq a0,zero,`:foo`\n"
    		+ "`ANY_BYTES{0,40}`                                      \n"
            + "`foo:`                                                 \n" +
            // Notice that this extra instruction moves the label one instruction earlier
            // than where the branch is pointing
            "sw zero,0x104(s2)                                      \n"
            + "lw a0,0x10c(s2)                                        \n";

    private static final String labelPatternBranch =
    		"lw a1,0x0(v0)\n"
    		+ "`foo:`\n"
            + "lw ra,0x1c(sp)\n"
    		+ "jr ra\n"
            + "addiu sp,sp,0x20\n" +
    		"clear a2\n"
            + "`ANY_BYTES{4,4}`\n"
    		+ "move a1,v0\n"
            + "b `:foo`\n"
    		+ "li v0,0x1\n";
    private static final String misalignedLabelPatternBranch =
    		"lw a1,0x0(v0)\n"
            + "lw ra,0x1c(sp)\n"
    		+ "`foo:`\n"
            + "jr ra\n"
    		+ "addiu sp,sp,0x20\n"
            + "clear a2\n"
            + "`ANY_BYTES{4,4}`\n"
            + "move a1,v0\n"
            + "b `:foo`\n"
            + "li v0,0x1\n";

    private static final String labelPatternBal =
    		"bal `:foo`\n"
    		+ "nop\n"
    		+ "`foo:`\n"
            + "`ANY_BYTES{1,1}`\n";
    private static final String misalignedLabelPatternBal =
    		"bal `:foo`\n"
            + "nop\n"
            + "`ANY_BYTES{4,4}`\n"
            + "`foo:`\n"
            + "`ANY_BYTES{1,1}`\n";

	private static final String restorePattern = "restore 0x1b8,ra,s0-s1";

	// The specifics of these steps have not been verified, but one of the choices
	// matches a value seen in an in-the-wild binary
	private static final String stepsForRestorePattern = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[240,56,100,119]},{\"operands\":[],\"value\":[240,52,100,119]},{\"operands\":[],\"value\":[240,60,100,119]},{\"operands\":[],\"value\":[240,62,100,119]},{\"operands\":[],\"value\":[240,48,100,119]}],\"mask\":[255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[],\"value\":[240,48,100,119]}],\"mask\":[255,240,255,255]}],\"type\":\"LOOKUP\"}";
	private static final String tablesForRestorePattern = "";

	private static final String restorePatternWild = "restore `Q1`,ra,s0-s1";
	// The specifics of these steps have not been verified
	private static final String stepsForRestorePatternWild = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"ConstantValue\",\"value\":128},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0]}],\"value\":[100,112]}],\"mask\":[255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,15]}],\"value\":[100,112]}],\"mask\":[255,240]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"ConstantValue\",\"value\":128},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,0]}],\"value\":[240,14,100,112]},{\"operands\":[{\"expression\":{\"op\":\"ConstantValue\",\"value\":128},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,0]}],\"value\":[240,12,100,112]},{\"operands\":[{\"expression\":{\"op\":\"ConstantValue\",\"value\":128},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,0]}],\"value\":[240,4,100,112]},{\"operands\":[{\"expression\":{\"op\":\"ConstantValue\",\"value\":128},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,0]}],\"value\":[240,8,100,112]}],\"mask\":[255,255,255,255]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,128,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,64,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,16,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,32,100,112]}],\"mask\":[255,240,255,240]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,30,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,128,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,64,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,28,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,32,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,20,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,24,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,14,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,46,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,12,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,44,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,140,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,76,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,16,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,142,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,78,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,136,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,72,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,4,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,36,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,132,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,68,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,8,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,40,100,112]}],\"mask\":[255,255,255,240]}],\"type\":\"LOOKUP\"}";
	// The specifics of these steps have not been verified
	private static final String stepsForRestorePatternWild1022 = "{\"data\":[{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,15]}],\"value\":[100,112]}],\"mask\":[255,240]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,32,100,112]}],\"mask\":[255,240,255,240]},{\"type\":\"MaskAndChoose\",\"choices\":[{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,14,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,46,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,12,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,44,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,32,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,4,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,36,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,8,100,112]},{\"operands\":[{\"expression\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"Or\",\"children\":{\"left\":{\"op\":\"LeftShift\",\"children\":{\"left\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"ContextField\",\"value\":{\"bitend\":9,\"shift\":6,\"signbit\":false,\"bitstart\":6,\"byteend\":1,\"bytestart\":0}}},\"right\":{\"op\":\"ConstantValue\",\"value\":4}}},\"right\":{\"op\":\"OperandValue\",\"offset\":0,\"child\":{\"op\":\"TokenField\",\"value\":{\"bitend\":3,\"shift\":0,\"signbit\":false,\"bitstart\":0,\"byteend\":1,\"bigendian\":true,\"bytestart\":1}}}}},\"right\":{\"op\":\"ConstantValue\",\"value\":3}}},\"var_id\":\"Q1\",\"type\":\"Scalar\",\"mask\":[0,0,0,15]}],\"value\":[240,40,100,112]}],\"mask\":[255,255,255,240]}],\"type\":\"LOOKUP\"}";

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("mips_test", "MIPS:BE:32:default");

		builder.setBytes("0x1008420",
				"8e 44 01 08 10 80 00 06 8f 82 80 2c 8c 59 00 00 03 20 f8 09 00 00 00 00 8f bc 00 28 ae 40 01 08 8e 44 01 0c 10 80 00 06");
		builder.setBytes("0x6000000", "04 11 00 01 00 00 00 00 3c 1c 00 06 04 11 ff 5a 00 00 00 00 8f bc 00 18");
		builder.setBytes("0x7000000",
				"8c 45 00 00 8f bf 00 1c 03 e0 00 08 27 bd 00 20 00 00 30 21 04 11 38 4e 00 40 28 21 10 00 ff f9 24 02 00 01");
		builder.applyDataType("0x1008420", new Pointer32DataType(), 1);
		builder.createLabel("0x1008420", "TEST_LABEL");
		builder.createLabel("0x1008424", "TEST_LABEL2");
		builder.createLabel("0x1000424", "TEST_LABEL3");
		// The following is:
		// 0x00000000: jalx 0x8
		// 0x00000004: nop
		// 0x00000008: restore 0x1b8,ra,s0-s1
		// 0x0000000c: nop
		builder.setBytes("0x00000000", "0c 00 00 08 00 00 00 00 f0 30 64 77 00 00 00 00");
		// This line sets the binary at addresses 0x8-0xc to be MIPS 16 (e.g. the
		// restore instruction above)
		builder.setRegisterValue("ISA_MODE", "0x8", "0xc", 1);
		builder.disassemble("0x00000000", 0x10);

		setup(builder);
	}

	@Test
	public void testBranch() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForBranchPattern + "],\"steps\":["
				+ stepsForBranchPattern + "]";
		generatePatternTestHelper(branchPattern, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testCVE_2019_3822() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForCVE_2019_3822 + "],\"steps\":["
				+ stepsForCVE_2019_3822 + "]";
		generatePatternTestHelper(CVE_2019_3822, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testMultipleNumericQs() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForMultipleNumericQs + "],\"steps\":["
				+ stepsForMultipleNumericQs + "]";
		generatePatternTestHelper(multipleNumericQs, testQueryPatternExpected + getCompileInfo());
	}

	@Test
	public void testLabelPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), labelPattern);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(0x1008440), result.labels.get("foo"));
	}

	@Test
	public void testMisalignedLabelPattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), misalignedLabelPattern);

		Assert.assertEquals(0, results.size());
	}

	@Test
	public void testLabelPatternBranch() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), labelPatternBranch);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(0x07000004), result.labels.get("foo"));
	}

	@Test
	public void testMisalignedLabelPatternBranch() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), misalignedLabelPatternBranch);

		Assert.assertEquals(0, results.size());
	}

	@Test
	public void testLabelPatternBal() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), labelPatternBal);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(0x6000008), result.labels.get("foo"));
	}

	@Test
	public void testMisalignedLabelPatternBal() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress(), misalignedLabelPatternBal);

		Assert.assertEquals(0, results.size());
	}

	@Test
	public void testRestore() {
		String testQueryPatternExpected = "{\"tables\":[" + tablesForRestorePattern + "],\"steps\":["
				+ stepsForRestorePattern + "]";

		generatePatternTestHelper(restorePattern,
				testQueryPatternExpected + getCompileInfo(this.program.getMinAddress().add(8)),
				this.program.getMinAddress().add(8));
	}

	@Test
	public void testRestorePattern() {
		List<SavedDataAddresses> results = PickledCanary.parseAndRunAll(monitor, this.program,
				this.program.getMinAddress().add(8), restorePattern);

		Assert.assertEquals(1, results.size());
		SavedDataAddresses result = results.get(0);
		Assert.assertEquals(this.program.getMinAddress().add(0x8), result.getStart());
	}

	@Test
	public void testRestoreWild() {

		List<String> testQueryPatternExpected = new ArrayList<>();
		testQueryPatternExpected.add("{\"tables\":[" + tablesForRestorePattern + "],\"steps\":["
				+ stepsForRestorePatternWild + "]" + getCompileInfo(this.program.getMinAddress().add(8)));
		testQueryPatternExpected.add("{\"tables\":[" + tablesForRestorePattern + "],\"steps\":["
				+ stepsForRestorePatternWild1022 + "]" + getCompileInfo(this.program.getMinAddress().add(8)));

		generatePatternTestHelper(restorePatternWild, testQueryPatternExpected, this.program.getMinAddress().add(8));
	}

	@Test
	public void fillBits() {
		Assert.assertEquals(0, AssemblyNumericTerminal.fillBits(0));
		Assert.assertEquals(1, AssemblyNumericTerminal.fillBits(1));
		Assert.assertEquals(3, AssemblyNumericTerminal.fillBits(2));
		Assert.assertEquals(7, AssemblyNumericTerminal.fillBits(3));
		Assert.assertEquals(0x7FFF, AssemblyNumericTerminal.fillBits(15));
	}

	@Test
	public void getOneBitLongs() {

		long[] o = AssemblyNumericTerminal.getOneBitLongs().toArray();

		Assert.assertEquals(65, o.length);
		Assert.assertEquals(0, o[0]);
		Assert.assertEquals(1, o[1]);
		Assert.assertEquals(-1, o[2]);
		Assert.assertEquals(-2147483648, o[63]);
	}

	int getArrayIndex(long[] arr, int val) {
		int out = -1;
		for (int i = 0; i < arr.length; i++) {
			if (arr[i] == val) {
				out = i;
				break;
			}
		}
		return out;
	}

	@Test
	public void testGetInterestingLongs() {

		long[] o = AssemblyNumericTerminal.getInterestingLongs(null).toArray();

		Assert.assertEquals(65, o.length);
		Assert.assertEquals(0, o[0]);
		Assert.assertEquals(1, o[1]);
		Assert.assertEquals(-1, o[2]);
		Assert.assertEquals(-2147483648, o[63]);

		long baseLong = 0x500000;

		Address base = this.program.getMinAddress().add(baseLong);
		o = AssemblyNumericTerminal.getInterestingLongs(base).toArray();

		Assert.assertEquals(159, o.length);
		Assert.assertEquals(0, o[0]);
		Assert.assertEquals(1, o[1]);
		Assert.assertEquals(-1, o[2]);
		Assert.assertEquals(baseLong + 1, o[66]);

		baseLong = 0x123456;

		base = this.program.getMinAddress().add(baseLong);
		o = AssemblyNumericTerminal.getInterestingLongs(base).toArray();

		// Make sure the masking out of addresses is working
		Assert.assertTrue(getArrayIndex(o, 0x123450) > -1);
		Assert.assertTrue(getArrayIndex(o, 0x123440) > -1);
		Assert.assertTrue(getArrayIndex(o, 0x123400) > -1);
		Assert.assertTrue(getArrayIndex(o, 0x123000) > -1);
	}
}
