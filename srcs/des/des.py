#!/nfshome/dslee/.b/python

## dslee    2017-04-02 23:18:53 -- initial release


import sys

# USAGE:
#   from (file name excluding ".py") import (module name)   : don't need to specify module hierarchy
#   import (file name excluding ".py")                      : must specify the hierarchy
try:
    from    des_core	import  des_core
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
SHOW_msg_residual_block=			1

SHOW_result_inMsg=					0
SHOW_result_outMsg=					0
SHOW_SOTB_CIPHER_SIM=				0


def	des( tdes, k, d, iv1, iv2, enc, opm, ivm, res, smsg ):

	# init session
	# 1) get pt_len, block_cnt
	# bs: block_size
	bs=8
	pt_len = int( len(d)/2 )
	if pt_len<bs:	block_cnt = 1
	else:			block_cnt = int(pt_len/bs) if (pt_len%bs == 0) else int(pt_len/bs+1)
	# 2) generate input/output message block list
	inMsg=	[ d[16*i:16*i+16] for i in range(block_cnt) ]
	outMsg=	[ d[16*i:16*i+16] for i in range(block_cnt) ]
	# 3) convert string to number
	if	tdes==1:
		k1=int(k[0:16],16)
		k2=int(k[16:32],16)
	else:
		k=	int(k,16)
	iv1=int(iv1,16)
	iv2=int(iv2,16)

	# setting display before crypto operation
	if	SHOW_algo==1: print( "# DES" )
	if	SHOW_key==1:
		if	tdes==1:
			print( "key1: %04x %04x %04x %04x" % ((k1>>48)&0xFFFF,(k1>>32)&0xFFFF,(k1>>16)&0xFFFF,(k1>> 0)&0xFFFF) )
			print( "key2: %04x %04x %04x %04x" % ((k2>>48)&0xFFFF,(k2>>32)&0xFFFF,(k2>>16)&0xFFFF,(k2>> 0)&0xFFFF) )
		else:
			print( "key : %04x %04x %04x %04x" % ((k>>48)&0xFFFF,(k>>32)&0xFFFF,(k>>16)&0xFFFF,(k>> 0)&0xFFFF) )
	if	SHOW_IV1==1: print( "IV1 : %04x %04x %04x %04x" % ((iv1>>48)&0xFFFF,(iv1>>32)&0xFFFF,(iv1>>16)&0xFFFF,(iv1>> 0)&0xFFFF) )
	if	SHOW_IV2==1: print( "IV2 : %04x %04x %04x %04x" % ((iv2>>48)&0xFFFF,(iv2>>32)&0xFFFF,(iv2>>16)&0xFFFF,(iv2>> 0)&0xFFFF) )
	# print enc
	if	SHOW_enc==1:
		if		enc==1:	print("Encryption")
		elif	enc==0:	print("Decryption")
	if	SHOW_pt_len==1:		print( "pt_len   = %d" % pt_len )
	if	SHOW_block_cnt==1:	print( "block_cnt= %d" % block_cnt )
	if	SHOW_inMsg==1: print( "msgBlk:", inMsg )
	if	SHOW_outMsg==1: print( "outMsg:", outMsg )

	# block processing
	# 0. IV setting
	try:				iv=iv1
	except NameError:	iv='0'*16

	# 1. solitary block
	if		pt_len < bs:
		if SHOW_msg_solitary_block==1: print( "input message is solitary, smsg=",smsg )
		if		smsg==0:
			pass
		else:
			if		smsg==1:	iv=iv1
			elif	smsg==2:	iv=iv2
			elif	smsg==3:	iv=iv1
			else:				sys.exit( "Unavailable smsg value" )
			if	tdes==1:
				ciph_out=	des_core(k1,des_core(k2,des_core( k1,iv,1 ),0),1)
			else:
				ciph_out=	des_core( k,iv,1 )
			#msgIN=		int( inMsg[0]+"0"*(16-2*pt_len) , 16 )
			msgIN=		int( inMsg[0].ljust( 16, '0' ) , 16 )
			outMsg[0]=	("%016x"%(ciph_out^msgIN))[0:pt_len*2]
	#2. not solitary block
	elif	pt_len==bs:
		if SHOW_msg_pt_len_16==1: print( "pt_len=8: input message is not solitary" )
		msgIN=int( inMsg[0] , 16 )
		if		enc==1:
			# ECB
			if		opm==0:
				if	tdes==1:
					outMsg[0]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,msgIN,1),0),1)
				else:
					outMsg[0]=	"%016x" % des_core(k,msgIN,1)
			# CBC
			elif	opm==1:
				ciph_in=	msgIN^iv
				if	tdes==1:
					outMsg[0]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
				else:
					outMsg[0]=	"%016x" % des_core(k,ciph_in,1)
		elif	enc==0:
			# ECB
			if		opm==0:
				if	tdes==1:
					outMsg[0]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,msgIN,0),1),0)
				else:
					outMsg[0]=	"%016x" % des_core(k,msgIN,0)
			# CBC
			elif	opm==1:
				if	tdes==1:
					ciph_out=	des_core(k1,des_core(k2,des_core(k1,msgIN,0),1),0)
				else:
					ciph_out=	des_core(k,msgIN,0)
				outMsg[0]=	"%016x" % (ciph_out^iv)
	else:
		if	SHOW_msg_pt_len_more_than_16==1: print( "pt_len>8: input message is not solitary" )
		block_end_idx =	block_cnt-1 if block_cnt>1 else 1
		for idx,msgIN in enumerate( inMsg[0:block_end_idx] ):
			msgIN=	int( msgIN,16 )
			if		enc==1:
				# ECB
				if		opm==0:
					if	tdes==1:
						outMsg[idx]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,msgIN,1),0),1)
					else:
						outMsg[idx]=	"%016x" % des_core(k,msgIN,1)
				# CBC
				elif	opm==1:
					ciph_in=		msgIN^iv
					if	tdes==1:
						outMsg[idx]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
					else:
						outMsg[idx]=	"%016x" % des_core(k,ciph_in,1)
					iv=				int(outMsg[idx],16)
			elif	enc==0:
				# ECB
				if		opm==0:
					if	tdes==1:
						outMsg[idx]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,msgIN,0),1),0)
					else:
						outMsg[idx]=	"%016x" % des_core(k,msgIN,0)
				# CBC
				elif	opm==1:
					if	tdes==1:
						ciph_out=		des_core(k1,des_core(k2,des_core(k1,msgIN,0),1),0)
					else:
						ciph_out=		des_core( k,msgIN,0 )
					outMsg[idx]=	"%016x" % (ciph_out^iv)
					iv=				msgIN
		if	SHOW_msg_end_of_block_processing==1: print( "block processing has finished except last block" )
		# last block handling
		# 1) last block is a full block
		if	len(inMsg[block_cnt-1])==16:
			msgIN=	int(inMsg[block_cnt-1],16)
			if		enc==1:
				# ECB
				if		opm==0:
					if	tdes==1:
						outMsg[block_cnt-1]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,msgIN,1),0),1)
					else:
						outMsg[block_cnt-1]=	"%016x" % des_core(k,msgIN,1)
				# CBC
				elif	opm==1:
					ciph_in=				msgIN^iv
					if	tdes==1:
						outMsg[block_cnt-1]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
					else:
						outMsg[block_cnt-1]=	"%016x" % des_core(k,ciph_in,1)
			else:
				# ECB
				if		opm==0:
					if	tdes==1:
						outMsg[block_cnt-1]=	"%016x" % des_core(k1,des_core(k2,des_core(k1,msgIN,0),1),0)
					else:
						outMsg[block_cnt-1]=	"%016x" % des_core(k,msgIN,0)
				# CBC
				elif	opm==1:
					if	tdes==1:
						ciph_out=				des_core(k1,des_core(k2,des_core(k1,msgIN,0),1),0)
					else:
						ciph_out=				des_core(k,msgIN,0)
					outMsg[block_cnt-1]=	"%016x" % (ciph_out^iv)
		# 2) last block is a residual block
		else:
			# encryption in residual block handling
			if		enc==1:
				if		res==0:
					if	SHOW_msg_residual_block==1: print( "res==0: last message block has been left as-is" )
					pass
				elif	res==1:
				# res=1: ECB_CTS1 follows Wikipedia, Nagravision ( "DES Payload ECB CTS Specification Version 1.0.0" )
					if		opm in [1,2,3,4,5]:
						if	SHOW_msg_residual_block==1: print( "res==1: res=1 ( standard ), opm= 1 ( CBC ) / 2,3 ( CPCM ) / 4,5 ( CTR ) --> not applicable" )
						pass
					elif	opm==0:
						# 0. Variables
						RBLEN=		len(inMsg[block_cnt-1])
						# 1. Generate Pn_1, Pn
						(Pn_1,Pn)=	(inMsg[block_cnt-2],inMsg[block_cnt-1])
						#print( "Enc     Pn_1:", Pn_1)
						#print( "Enc     Pn  :", Pn)
						# 2. Encrypt Pn_1
						ciph_in=	int( Pn_1,16 )
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,1)
						(tmpCn_1_HEAD,tmpCn_1_TAIL)=	(ciph_out[0:RBLEN],ciph_out[RBLEN:])
						#print( "Enc tmpCn_1H:", tmpCn_1_HEAD)
						#print( "Enc tmpCn_1T:", tmpCn_1_TAIL)
						# 3. Encrypt Pn
						ciph_in=	int( Pn + tmpCn_1_TAIL,16)
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,1)
						tmpCn=	ciph_out
						#print( "Enc tmpCn   :", tmpCn)
						# 4. Generate Cn_1, Cn
						outMsg[block_cnt-2]=	tmpCn
						outMsg[block_cnt-1]=	tmpCn_1_HEAD
						#print( "Enc CT      :", outMsg[block_cnt-2], outMsg[block_cnt-1])
				elif	res==2:
				# res=2: ECB_CTS2 follows CableCARD way ( CableCARD Copy Protection 2.0 Specification )
					if		opm in [1,2,3,4,5]:
						if	SHOW_msg_residual_block==1: print( "res==2: res=2 ( CableCARD ), opm= 1 ( CBC ) / 2,3 ( CPCM ) / 4,5 ( CTR ) --> not applicable" )
						pass
					elif	opm==0:
						# 0. Variables
						RBLEN=len(inMsg[block_cnt-1])
						# 1. Generate Pn_1 and Pn
						(Pn_1,Pn)=	(inMsg[block_cnt-2][0:RBLEN],inMsg[block_cnt-2][RBLEN:]+inMsg[block_cnt-1])
						#print( "Enc     Pn_1:", Pn_1)
						#print( "Enc     Pn  :", Pn)
						# 2. Encrypt Pn
						ciph_in=	int(Pn,16)
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,1)
						(tmpCn_HEAD,tmpCn_TAIL)=	(ciph_out[0:16-RBLEN],ciph_out[16-RBLEN:])
						#print( "Enc  tmpCn_H:", tmpCn_HEAD)
						#print( "Enc  tmpCn_T:", tmpCn_TAIL)
						# 3. Encrypt Pn_1
						ciph_in=	int(Pn_1+tmpCn_HEAD,16)
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,1)
						tmpCn_1=	ciph_out
						#print( "Enc tmpCn_1 :", tmpCn_1)
						# 4. Generate Cn_1, Cn
						outMsg[block_cnt-2]=	tmpCn_1
						outMsg[block_cnt-1]=	tmpCn_TAIL
						#print( "Enc CT      :", outMsg[block_cnt-2], outMsg[block_cnt-1])
				elif	res==3:
				# res=3: CBC-CS2 ( Addendum to SP800-38A -- CTS for CBC Mode, NIST )
					if		opm in [0,2,3,4,5]:
						if	SHOW_msg_residual_block==1: print( "res==3: res=3 ( CBC-CS2 ), opm= 0 ( ECB ) / 2,3 ( CPCM ) / 4,5 ( CTR ) --> not applicable" )
						pass
					elif	opm==1:
						# 0. Variables
						RBLEN=		len(inMsg[block_cnt-1])
						# 1. Generate tmpCn_1, Pn_pad
						tmpCn_1=	outMsg[block_cnt-2]
						Pn_pad=		inMsg[block_cnt-1]+"0"*( 16-RBLEN )
						# 2. Encrypt Pn
						ciph_in=	int(Pn_pad,16)^int(tmpCn_1,16)
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,1)
						tmpCn=	ciph_out
						# 3. Divide Cn_1
						(tmpCn_1_HEAD,tmpCn_1_TAIL)=	(tmpCn_1[0:RBLEN],tmpCn_1[RBLEN:])
						# 4. Generate Cn_1, Cn
						if		len(inMsg[block_cnt-1])<16:
							outMsg[block_cnt-2]=	tmpCn
							outMsg[block_cnt-1]=	tmpCn_1_HEAD
						else:
							outMsg[block_cnt-2]=	tmpCn_1_HEAD
							outMsg[block_cnt-1]=	tmpCn
						if	SHOW_msg_residual_block==1: print( "res==3: residual block has been processed as CBC CTS: CBC-CS2 ( ref: NIST SP800-38A Addendum )" )
				elif	res==4:
				# res=4: SCTE52 way
					if		opm in [0,2,3,4,5]:
						if	SHOW_msg_residual_block==1: print( "res==4: CBC mode is required, override to res=0, this config is for SCTE52, ATIS, DVS-042 termination" )
						pass
					elif	opm==1:
						# 1. Generate Cn_1, Pn
						Cn_1=		outMsg[block_cnt-2]
						Pn=			inMsg[block_cnt-1]
						# 2. Encrypt Cn_1
						ciph_in=		int(Cn_1,16)
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,1)
						# 3. Generate Cn
						Pn_pad=		Pn+"0"*(16-len(Pn))
						outMsg[block_cnt-1]= ("%016x"%(int(ciph_out,16)^int(Pn_pad,16)))[0:len(Pn)]
						if	SHOW_msg_residual_block==1: print( "res==2: ( enc ) residual block has been processed as described in SCTE52, ATIS, DVS-042 termination" )
				elif	res==5:
					if	SHOW_msg_residual_block==1: print( "res==5: this config is for stream cipher, current algo is DES, override to res=0" )
					pass
			# decryption in residual block handling
			elif	enc==0:
				if		res==0:
					if	SHOW_msg_residual_block==1: print( "res==0: last message block has been left as-is" )
					pass
				elif	res==1:
				# res=1: ECB_CTS1 follows Wikipedia, Nagravision ( "DES Payload ECB CTS Specification Version 1.0.0" )
					if		opm in [1,2,3,4,5]:
						if	SHOW_msg_residual_block==1: print( "res==1: res=1 ( standard ), opm= 1 ( CBC ) / 2,3 ( CPCM ) / 4,5 ( CTR ) --> not applicable" )
						pass
					elif	opm==0:
						# 0. Variables
						RBLEN=		len(inMsg[block_cnt-1])
						# 1. Generate Cn_1, Cn
						(Cn_1,Cn)=	(inMsg[block_cnt-2],inMsg[block_cnt-1])
						#print( "Dec     Cn_1:", Cn_1)
						#print( "Dec     Cn  :", Cn)
						# 2. Decrypt Cn_1
						ciph_in=	int( Cn_1,16 )
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,0),1),0)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,0)
						(tmpPn_1_HEAD,tmpPn_1_TAIL)=	(ciph_out[0:RBLEN],ciph_out[RBLEN:])
						#print( "Dec tmpPn_1H:", tmpPn_1_HEAD)
						#print( "Dec tmpPn_1T:", tmpPn_1_TAIL)
						# 3. Decrypt Cn
						ciph_in=	int( Cn + tmpPn_1_TAIL,16)
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,0),1),0)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,0)
						tmpPn=	ciph_out
						#print( "Dec tmpPn   :", tmpPn)
						# 4. Generate Pn_1, Pn
						outMsg[block_cnt-2]=	tmpPn
						outMsg[block_cnt-1]=	tmpPn_1_HEAD
						print( "Dec PT      :", outMsg[block_cnt-2], outMsg[block_cnt-1])
				# res=2: ECB_CTS2 follows CableCARD way ( CableCARD Copy Protection 2.0 Specification )
				elif	res==2:
					# 0. Variables
					RBLEN=len(inMsg[block_cnt-1])
					# 1. Generate Cn_1, Cn
					(Cn_1,Cn)=	(inMsg[block_cnt-2],inMsg[block_cnt-1])
					#print( "DEC|    Cn_1:", Cn_1[0:4], Cn_1[4:8], Cn_1[8:12], Cn_1[12:16])
					#print( "DEC|      Cn:", Cn[0:4], Cn[4:8], Cn[8:12], Cn[12:16])
					# 2. Decrypt Cn_1
					ciph_in=	int( Cn_1,16 )
					if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,0),1),0)
					else:			ciph_out=	"%016x" % des_core(k,ciph_in,0)
					(tmpPn_1_HEAD,tmpPn_1_TAIL)=	(ciph_out[0:RBLEN],ciph_out[RBLEN:])
					#print( "DEC|tmpPn_1H:", tmpPn_1_HEAD[0:4], tmpPn_1_HEAD[4:8], tmpPn_1_HEAD[8:12], tmpPn_1_HEAD[12:16])
					#print( "DEC|tmpPn_1T:", tmpPn_1_TAIL[0:4], tmpPn_1_TAIL[4:8], tmpPn_1_TAIL[8:12], tmpPn_1_TAIL[12:16])
					# 3. Decrypt Cn
					ciph_in=	int( tmpPn_1_TAIL + Cn,16)
					if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,0),1),0)
					else:			ciph_out=	"%016x" % des_core(k,ciph_in,0)
					tmpPn=	ciph_out
					print( "DEC|  tmpPnT:", tmpPn_1_TAIL[0:4], tmpPn_1_TAIL[4:8], tmpPn_1_TAIL[8:12], tmpPn_1_TAIL[12:16])
					# 4. Generate Pn_1, Pn
					outMsg[block_cnt-2]=	tmpPn_1_HEAD
					outMsg[block_cnt-1]=	tmpPn
				elif	res==3:
				# res=3: CBC-CS2 ( Addendum to SP800-38A -- CTS for CBC Mode, NIST )
					if		opm in [0,2,3,4,5]:
						if	SHOW_msg_residual_block==1: print( "res==3: res=3 ( CBC-CS2 ), opm= 0 ( ECB ) / 2,3 ( CPCM ) / 4,5 ( CTR ) --> not applicable" )
						pass
					elif	opm==1:
						if		block_cnt==2:	Cn_2= iv1
						elif	block_cnt>2:	Cn_2= int( inMsg[block_cnt-3] , 16 )
						Cn_1=		int( inMsg[block_cnt-2] , 16 )
						Cn=			inMsg[block_cnt-1]
						if		len(Cn)<16:
							# 1. Decrypt Cn_1
							if	tdes==1:
								tmp_Pn=		"%016x" % des_core(k1,des_core(k2,des_core(k1,Cn_1,0),1),0)
							else:
								tmp_Pn=		"%016x" % des_core(k,Cn_1,0)
							# 2. Divide tmp_Pn into tmp_Pn1, tmp_Pn2
							tmp_Pn1=	tmp_Pn[0:len(Cn)]
							tmp_Pn2=	tmp_Pn[len(Cn):]
							# 3. Concatenate Cn and tmp_Pn2
							tmp_Pn_1=	int(Cn+tmp_Pn2,16)
							# 4. Decrypt tmp_Cn and XOR decryption result and Cn_2
							if	tdes==1:
								Pn_1=		"%016x" % (Cn_2^des_core(k1,des_core(k2,des_core(k1,tmp_Pn_1,0),1),0))
							else:
								Pn_1=		"%016x" % (Cn_2^des_core(k,tmp_Pn_1,0))
							# 5. XOR tmp_Pn1 and Cn, resulting block is Pn
							tmp_Pn1_pad=	tmp_Pn1+"0"*(16-len(tmp_Pn1))
							Cn_pad=			Cn     +"0"*(16-len(Cn))
							Pn=			("%016x"%(int(tmp_Pn1_pad,16)^int(Cn_pad,16)))[0:len(Cn)]
							# 6. Generate output block
							outMsg[block_cnt-2]=	Pn_1
							outMsg[block_cnt-1]=	Pn
						else:
							# same with normal CBC decryption
							if	tdes==1:
								outMsg[block_cnt-2]=	"%016x"%(des_core(k1,des_core(k2,des_core(k1,Cn_1,0),1),0)^Cn_2)
								outMsg[block_cnt-1]=	"%016x"%(des_core(k1,des_core(k2,des_core(k1,Cn,0),1),0)^Cn_1)
							else:
								outMsg[block_cnt-2]=	"%016x"%(des_core(k,Cn_1,0)^Cn_2)
								outMsg[block_cnt-1]=	"%016x"%(des_core(k,Cn,0)^Cn_1)
						if	SHOW_msg_residual_block==1: print( "res==1: CBC CTS: CBC-CS2 ( ref: NIST SP800-38A Addendum )" )
				elif	res==4:
				# res=4: SCTE 52 way
					if		opm in [0,2,3,4,5]:
						if	SHOW_msg_residual_block==1: print( "res==4: CBC mode is required, override to res=0, this config is for SCTE52, ATIS, DVS-042 termination" )
						pass
					elif	opm==1:
						# 1. Generate Cn_1, Cn
						Cn_1=		inMsg[block_cnt-2]
						Cn=			inMsg[block_cnt-1]
						# 2. Encrypt Cn_1
						ciph_in=	int( Cn_1,16 )
						if	tdes==1:	ciph_out=	"%016x" % des_core(k1,des_core(k2,des_core(k1,ciph_in,1),0),1)
						else:			ciph_out=	"%016x" % des_core(k,ciph_in,1)
						# 3. Generate Pn
						Cn_pad=		Cn+"0"*(16-len(Cn))
						outMsg[block_cnt-1]= ("%016x"%(int(ciph_out,16)^int(Cn_pad,16)))[0:len(Cn)]
						if	SHOW_msg_residual_block==1: print( "res==2: ( dec ) residual block has been processed as described in SCTE52, ATIS, DVS-042 termination" )
				elif	res==5:
					if	SHOW_msg_residual_block==1: print( "res==5: this config is for stream cipher, current algo is DES, override to res=0" )
					pass

	# result printing: original ver.
#	# result printing
#	if	SHOW_result_inMsg==1:
#		for i,blk	in enumerate( inMsg ):
#			print( " inMsg[%3d]=" % i, blk[0:0+4],blk[4:4+4],blk[8:8+4],blk[12:12+4],blk[16:16+4],blk[20:20+4],blk[24:24+4],blk[28:28+4])
#	if	SHOW_result_outMsg==1:
#		for i,blk	in enumerate( outMsg ):
#			print( "outMsg[%3d]=" % i, blk[0:0+4],blk[4:4+4],blk[8:8+4],blk[12:12+4],blk[16:16+4],blk[20:20+4],blk[24:24+4],blk[28:28+4])

	# result printing: for sim and s/w ref compare only
	if	SHOW_SOTB_CIPHER_SIM==1:
		# calculate mem block length of a single line
		inMsg= "".join( inMsg )
		outMsg= "".join( outMsg )
		bs=16
		pt_len = int( len(inMsg)/2 )
		if pt_len<bs:	block_cnt = 1
		else:			block_cnt = int(pt_len/bs) if (pt_len%bs == 0) else int(pt_len/bs+1)
		# generate input/output message block list
		iML=[ inMsg[32*i:32*i+32] for i in range(block_cnt)]	# iML: inMsgList
		oML=[ outMsg[32*i:32*i+32] for i in range(block_cnt)]	# oML: outMsgList
		for i	in range( len( iML ) ):
			if len(iML[i]) < 32:	iML[i] += "0"*(32-len(iML[i]))
			if len(oML[i]) < 32:	oML[i] += "0"*(32-len(oML[i]))
			print( "in[%3d]=" % i, iML[i][0:0+4],iML[i][4:4+4],iML[i][8:8+4],iML[i][12:12+4],iML[i][16:16+4],iML[i][20:20+4],iML[i][24:24+4],iML[i][28:28+4], end="\t")
			print( "out[%3d]=" % i, oML[i][0:0+4],oML[i][4:4+4],oML[i][8:8+4],oML[i][12:12+4],oML[i][16:16+4],oML[i][20:20+4],oML[i][24:24+4],oML[i][28:28+4])

	return	"".join( outMsg )


