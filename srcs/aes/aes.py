import sys

# USAGE:
#   from (file name excluding ".py") import (module name)   : don't need to specify module hierarchy
#   import (file name excluding ".py")                      : must specify the hierarchy
try:
    from    aes_core	import  aesKBR, aes_core
except ImportError as e:
    print( e )

# DEBUG_controls
SHOW_algo=							0
SHOW_key=							0
SHOW_IV1=							0
SHOW_IV2=							0
SHOW_enc=							0
SHOW_pt_len=						0
SHOW_block_cnt=						0
SHOW_inMsg=							0
SHOW_outMsg=						0
SHOW_msg_solitary_block=			0
SHOW_msg_pt_len_16=					0
SHOW_msg_pt_len_more_than_16=		0
SHOW_msg_end_of_block_processing=	0
SHOW_msg_residual_block=			0
SHOW_result_inMsg=					1
SHOW_result_outMsg=					1
SHOW_CIPHER_SIM=				1

def	aes( k, d, iv1, iv2, enc, opm, ivm, res, smsg ):

	# init session
	# 1) get pt_len, block_cnt
	# bs: block_size
	bs=16
	pt_len = int( len(d)/2 )
	if pt_len<bs:	block_cnt = 1
	else:			block_cnt = int(pt_len/bs) if (pt_len%bs == 0) else int(pt_len/bs+1)
	# 2) generate input/output message block list
	inMsg=[ d[32*i:32*i+32] for i in range(block_cnt)]
	outMsg=[ d[32*i:32*i+32] for i in range(block_cnt)]


	# setting display before crypto operation
	if SHOW_algo==1: print( "# AES" )
	try:
		if SHOW_algo==1: print("\nAES-%d\t(Nk,Nb,Nr)=(%d,%d,%d)" % (len(k)*4, aesKBR(k)[0],aesKBR(k)[1],aesKBR(k)[2]) )
	except NameError:
		sys.exit("aes_main: Key and data info are not exist")
	# print key
	if	SHOW_key==1:
		if   len(k)==32: print( "key: %s %s %s %s %s %s %s %s" % (k[0:4],k[4:8],k[8:12],k[12:16],k[16:20],k[20:24],k[24:28],k[28:32]) )
		elif len(k)==48: print( "key: %s %s %s %s %s %s %s %s %s %s %s %s" % (k[0:4],k[4:8],k[8:12],k[12:16],k[16:20],k[20:24],k[24:28],k[28:32],k[32:36],k[36:40],k[40:44],k[44:48]) )
		elif len(k)==64: print( "key: %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s" % (k[0:4],k[4:8],k[8:12],k[12:16],k[16:20],k[20:24],k[24:28],k[28:32],k[32:36],k[36:40],k[40:44],k[44:48],k[48:52],k[52:56],k[56:60],k[60:64]) )
		else           : sys.exit("aes: Invalid key length.")
	# print IV1
	if	SHOW_IV1==1:
		print( "IV1: %s %s %s %s %s %s %s %s" % (iv1[0:4],iv1[4:8],iv1[8:12],iv1[12:16],iv1[16:20],iv1[20:24],iv1[24:28],iv1[28:32]) )
	# print IV2
	if	SHOW_IV2==1:
		print( "IV2: %s %s %s %s %s %s %s %s" % (iv2[0:4],iv2[4:8],iv2[8:12],iv2[12:16],iv2[16:20],iv2[20:24],iv2[24:28],iv2[28:32]) )
	# print enc
	if	SHOW_enc==1:
		if		enc==1:	print("Encryption")
		elif	enc==0:	print("Decryption")
	if	SHOW_pt_len==1: print( "pt_len   = %d" % pt_len )
	if	SHOW_block_cnt==1: print( "block_cnt= %d" % block_cnt )
	if	SHOW_inMsg==1: print( "msgBlk:", inMsg )
	if	SHOW_outMsg==1: print( "outMsg:", outMsg )

	# block processing
	# 0. IV setting
	try:				iv=iv1
	except NameError:	iv='0'*32

	#1. solitary block
	if		pt_len < bs:
		if SHOW_msg_solitary_block==1: print( "input message is solitary, smsg=",smsg )
		if		smsg==0:
			pass
		else:
			if		smsg==1:	iv=iv1
			elif	smsg==2:	iv=iv2
			#elif	smsg==3:	sys.exit( "counter mode" )
			elif	smsg==3:	iv=iv1
			else:				sys.exit( "Unavailable smsg value" )
			ciph_out=	aes_core( k,iv,1 )
			#msgIN=		inMsg[0]+"0"*(32-len(inMsg[0]))
			#msgIN=		msgIN.ljust( 32,'0' )
			msgIN=		inMsg[0].ljust( 32,'0' )
			outMsg[0]=	("%032x"%(int(ciph_out,16)^int(msgIN,16)))[0:len(inMsg[0])]
			#oTxt= iv
			#print( "iv      :", oTxt[0:4], oTxt[4:8], oTxt[8:12], oTxt[12:16], oTxt[16:20], oTxt[20:24], oTxt[24:28], oTxt[28:32])
			#oTxt= ciph_out
			#print( "ciph_out:", oTxt[0:4], oTxt[4:8], oTxt[8:12], oTxt[12:16], oTxt[16:20], oTxt[20:24], oTxt[24:28], oTxt[28:32])
			#oTxt= msgIN
			#print( "msgIN   :", oTxt[0:4], oTxt[4:8], oTxt[8:12], oTxt[12:16], oTxt[16:20], oTxt[20:24], oTxt[24:28], oTxt[28:32])
			#oTxt= outMsg[0]
			#print( "outMsg  :", oTxt[0:4], oTxt[4:8], oTxt[8:12], oTxt[12:16], oTxt[16:20], oTxt[20:24], oTxt[24:28], oTxt[28:32])
	#2. not solitary block
	elif	pt_len==bs:
		if SHOW_msg_pt_len_16==1: print( "pt_len==16: input message is not solitary" )
		msgIN=inMsg[0]
		if		enc==1:
			# ECB
			if		opm==0:
				outMsg[0]=	aes_core( k,msgIN,1 )
			# CBC
			elif	opm==1:
				ciph_in=	"%032x" % (int(msgIN,16)^int(iv,16))
				outMsg[0]=	aes_core( k,ciph_in,1 )
			# CTR 
			elif	opm==4:
				ciph_out=	aes_core( k,iv,1 )
				outMsg[0]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
			# CTR64 
			elif	opm==5:
				ciph_out=	aes_core( k,iv,1 )
				outMsg[0]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
		elif	enc==0:
			# ECB
			if		opm==0:
				outMsg[0]=	aes_core( k,msgIN,0 )
			# CBC
			elif	opm==1:
				ciph_out=	aes_core( k,msgIN,0 )
				outMsg[0]=	"%032x" % (int(ciph_out,16)^int(iv,16))
			# CTR 
			elif	opm==4:
				ciph_out=	aes_core( k,iv,1 )
				outMsg[0]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
			# CTR64 
			elif	opm==5:
				ciph_out=	aes_core( k,iv,1 )
				outMsg[0]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
	else:
		if	SHOW_msg_pt_len_more_than_16==1: print( "pt_len>16: input message is not solitary" )
		block_end_idx =	block_cnt-1 if block_cnt>1 else 1
		for idx,msgIN in enumerate( inMsg[0:block_end_idx] ):
			if		enc==1:
				# ECB
				if		opm==0:
					outMsg[idx]=	aes_core( k,msgIN,1 )
				# CBC
				elif	opm==1:
					ciph_in=		"%032x" % (int(msgIN,16)^int(iv,16))
					outMsg[idx]=	aes_core( k,ciph_in,1 )
					iv=				outMsg[idx]
				# CTR 
				elif	opm==4:
					ciph_out=		aes_core( k,iv,1 )
					outMsg[idx]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
					iv=				"%032x" % ((int(iv,16)+1)&0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
				# CTR64 
				elif	opm==5:
					ciph_out=		aes_core( k,iv,1 )
					outMsg[idx]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
					iv=				iv[0:16] + ("%016x" % ((int(iv[16:32],16)+1)&0xFFFFFFFFFFFFFFFF))
			elif	enc==0:
				# ECB
				if		opm==0:
					outMsg[idx]=	aes_core( k,msgIN,0 )
				# CBC
				elif	opm==1:
					ciph_out=		aes_core( k,msgIN,0 )
					outMsg[idx]=	"%032x" % (int(ciph_out,16)^int(iv,16))
					iv=				msgIN
				# CTR 
				elif	opm==4:
					ciph_out=		aes_core( k,iv,1 )
					outMsg[idx]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
					iv=				"%032x" % ((int(iv,16)+1)&0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
				# CTR64 
				elif	opm==5:
					ciph_out=		aes_core( k,iv,1 )
					outMsg[idx]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
					iv=				iv[0:16] + ("%016x" % ((int(iv[16:32],16)+1)&0xFFFFFFFFFFFFFFFF))
		if	SHOW_msg_end_of_block_processing==1: print( "block processing has finished except last block" )
		# last block handling
		# 1) last block is a full block
		if	len(inMsg[block_cnt-1])==32:
			msgIN=	inMsg[block_cnt-1]
			if		enc==1:
				# ECB
				if		opm==0:
					outMsg[block_cnt-1]=	aes_core( k,msgIN,1 )
				# CBC
				elif	opm==1:
					ciph_in=				"%032x" % (int(msgIN,16)^int(iv,16))
					outMsg[block_cnt-1]=	aes_core( k,ciph_in,1 )
				# CTR and CTR64
				elif	opm in [4,5]:
					ciph_out=				aes_core( k,iv,1 )
					outMsg[block_cnt-1]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
					#iv=						"%032x" % ((int(iv,16)+1)&0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
			else:
				# ECB
				if		opm==0:
					outMsg[block_cnt-1]=	aes_core( k,msgIN,0 )
				# CBC
				elif	opm==1:
					ciph_out=				aes_core( k,msgIN,0 )
					outMsg[block_cnt-1]=	"%032x" % (int(ciph_out,16)^int(iv,16))
				# CTR and CTR64
				elif	opm in [4,5]:
					ciph_out=				aes_core( k,iv,1 )
					outMsg[block_cnt-1]=	"%032x" % (int(ciph_out,16)^int(msgIN,16))
					#iv=						"%032x" % ((int(iv,16)+1)&0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
		# 2) last block is a residual block
		else:
			if		enc==1:
				if		res==0:
					if	SHOW_msg_residual_block==1: print( "res==0: last message block has been left as-is" )
				elif	res==1:
					if		opm in [0,5,6]:
						if	SHOW_msg_residual_block==1: print( "res==1: CBC mode is required, override to res=0, ECB CTS is not supported" )
					elif	opm==1:
						Cn_1=		outMsg[block_cnt-2]
						Pn=			inMsg[block_cnt-1]
						Pn_pad=		Pn+"0"*(32-len(Pn))
						ciph_in=	"%032x" % (int(Pn_pad,16)^int(Cn_1,16))
						ciph_out=	aes_core( k,ciph_in,1 )
						if		len(Pn)<32:
							outMsg[block_cnt-2]=	ciph_out
							outMsg[block_cnt-1]=	Cn_1[0:len(Pn)]
						else:
							outMsg[block_cnt-2]=	Cn_1[0:len(Pn)]
							outMsg[block_cnt-1]=	ciph_out
						if	SHOW_msg_residual_block==1: print( "res==1: residual block has been processed as CBC CTS: CBC-CS2 ( ref: NIST SP800-38A Addendum )" )
				elif	res==2:
					if		opm in [0,5,6]:
						if	SHOW_msg_residual_block==1: print( "res==2: CBC mode is required, override to res=0, this config is for SCTE52, ATIS, DVS-042 termination" )
					elif	opm==1:
						Cn_1=		outMsg[block_cnt-2]
						ciph_out=	aes_core( k,Cn_1,1 )
						Pn=			inMsg[block_cnt-1]
						Pn_pad=		Pn+"0"*(32-len(Pn))
						outMsg[block_cnt-1]= ("%032x"%(int(ciph_out,16)^int(Pn_pad,16)))[0:len(Pn)]
						if	SHOW_msg_residual_block==1: print( "res==2: residual block has been processed as described in SCTE52, ATIS, DVS-042 termination" )
				elif	res==3:
					if	SHOW_msg_residual_block==1: print( "res==3: AES counter mode" )
					# CTR and CTR64
					if	opm in [4,5]:
						Pn=			inMsg[block_cnt-1]
						Pn_pad=		Pn.ljust( 32, '0' )
						ciph_out=	aes_core( k,iv,1 )
						msgIN=	msgIN.ljust( 32, '0' )
						outMsg[block_cnt-1]=	("%032x" % (int(ciph_out,16)^int(Pn_pad,16)))[0:len(Pn)]
			elif	enc==0:
				if		res==0:
					if	SHOW_msg_residual_block==1: print( "res==0: last message block has been left as-is" )
				elif	res==1:
					if		opm in [0,5,6]:
						if	SHOW_msg_residual_block==1: print( "res==1: CBC mode is required, override to res=0, ECB CTS is not supported" )
					elif	opm==1:
						if		block_cnt==2:	Cn_2= iv1
						elif	block_cnt>2:	Cn_2= inMsg[block_cnt-3]
						Cn_1=		inMsg[block_cnt-2]
						Cn=			inMsg[block_cnt-1]
						if		len(Cn)<32:
							# 1. Decrypt Cn_1
							tmp_Pn=		aes_core( k, Cn_1, 0 )
							# 2. Divide tmp_Pn into tmp_Pn1, tmp_Pn2
							tmp_Pn1=	tmp_Pn[0:len(Cn)]
							tmp_Pn2=	tmp_Pn[len(Cn):]
							# 3. Concatenate Cn and tmp_Pn2
							tmp_Cn=		Cn+tmp_Pn2
							# 4. Decrypt tmp_Cn and XOR decryption result and Cn_2
							Pn_1=		"%032x" % (int(Cn_2,16)^int(aes_core(k,tmp_Cn,0),16))
							# 5. XOR tmp_Pn1 and Cn, resulting block is Pn
							tmp_Pn1_pad=	tmp_Pn1+"0"*(32-len(tmp_Pn1))
							Cn_pad=			Cn     +"0"*(32-len(Cn))
							Pn=			("%032x"%(int(tmp_Pn1_pad,16)^int(Cn_pad,16)))[0:len(Cn)]
							# 6. Generate output block
							outMsg[block_cnt-2]=	Pn_1
							outMsg[block_cnt-1]=	Pn
						else:
							# same with normal CBC decryption
							outMsg[block_cnt-2]=	"%032x"%(int(aes_core(k,Cn_1,0),16)^int(Cn_2,16))
							outMsg[block_cnt-1]=	"%032x"%(int(aes_core(k,Cn,0),16)^int(Cn_1,16))
						if	SHOW_msg_residual_block==1: print( "res==1: CBC CTS: CBC-CS2 ( ref: NIST SP800-38A Addendum )" )
				elif	res==2:
					if		opm in [0,5,6]:
						if	SHOW_msg_residual_block==1: print( "res==2: CBC mode is required, override to res=0, this config is for SCTE52, ATIS, DVS-042 termination" )
					elif	opm==1:
						Cn_1=		inMsg[block_cnt-2]
						ciph_out=	aes_core( k,Cn_1,1 )
						Cn=			inMsg[block_cnt-1]
						if	SHOW_msg_residual_block==1: print( "Cn:",Cn )
						Cn_pad=		Cn+"0"*(32-len(Cn))
						outMsg[block_cnt-1]= ("%032x"%(int(ciph_out,16)^int(Cn_pad,16)))[0:len(Cn)]
						if	SHOW_msg_residual_block==1: print( "res==2: for SCTE52, ATIS, DVS-042 termination" )
				elif	res==3:
					if	SHOW_msg_residual_block==1: print( "res==3: AES counter mode" )
					# CTR and CTR64
					if	opm in [4,5]:
						Pn=			inMsg[block_cnt-1]
						Pn_pad=		Pn.ljust( 32, '0' )
						ciph_out=	aes_core( k,iv,1 )
						outMsg[block_cnt-1]=	("%032x" % (int(ciph_out,16)^int(Pn_pad,16)))[0:len(Pn)]



	# result printing: original ver.
#	for i	in range( len( inMsg ) ):
#		print( " in[%3d]=" % i, inMsg[i][0:0+4],inMsg[i][4:4+4],inMsg[i][8:8+4],inMsg[i][12:12+4],inMsg[i][16:16+4],inMsg[i][20:20+4],inMsg[i][24:24+4],inMsg[i][28:28+4], end="\t")
#		print( "out[%3d]=" % i, outMsg[i][0:0+4],outMsg[i][4:4+4],outMsg[i][8:8+4],outMsg[i][12:12+4],outMsg[i][16:16+4],outMsg[i][20:20+4],outMsg[i][24:24+4],outMsg[i][28:28+4])

	# result printing: for sim and s/w ref compare only
	if	SHOW_CIPHER_SIM==1:
		for i	in range( len( inMsg ) ):
			if len(inMsg[i]) < 32:	inMsg[i] += "0"*(32-len(inMsg[i]))
			if len(outMsg[i]) < 32:	outMsg[i] += "0"*(32-len(outMsg[i]))
			print( "in[%3d]=" % i, inMsg[i][0:0+4],inMsg[i][4:4+4],inMsg[i][8:8+4],inMsg[i][12:12+4],inMsg[i][16:16+4],inMsg[i][20:20+4],inMsg[i][24:24+4],inMsg[i][28:28+4], end="\t")
			print( "out[%3d]=" % i, outMsg[i][0:0+4],outMsg[i][4:4+4],outMsg[i][8:8+4],outMsg[i][12:12+4],outMsg[i][16:16+4],outMsg[i][20:20+4],outMsg[i][24:24+4],outMsg[i][28:28+4])

	return	"".join( outMsg )
