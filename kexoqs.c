/*
* Copyright 2018 Amazon.com, Inc. or its affiliates. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "includes.h"

#ifdef WITH_OQS

#include <string.h>

#include "ssherr.h"
#include "packet.h"
#include "ssh2.h"
#include "kexoqs.h"

/*
 * Mapping that maps relevant named SSH key exchange methods to the needed
 * corresponding liboqs key exchange scheme
 */
static const OQS_ALG oqs_alg_mapping[] = {
/* Hybrid key exchange methods */
#if defined(OPENSSL_HAS_ECC) && defined(WITH_HYBRID_KEX)
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-oqsdefault-sha384"), OQS_KEM_alg_default,
	SSH2_MSG_HY_ECDH_OQSDEFAULT_INIT, SSH2_MSG_HY_ECDH_OQSDEFAULT_REPLY},
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_START
#ifdef HAVE_BIKE
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l1-cpa-sha384"), OQS_KEM_alg_bike1_l1_cpa,
	SSH2_MSG_HY_ECDH_BIKE_INIT, SSH2_MSG_HY_ECDH_BIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l3-cpa-sha384"), OQS_KEM_alg_bike1_l3_cpa,
	SSH2_MSG_HY_ECDH_BIKE_INIT, SSH2_MSG_HY_ECDH_BIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l1-fo-sha384"), OQS_KEM_alg_bike1_l1_fo,
	SSH2_MSG_HY_ECDH_BIKE_INIT, SSH2_MSG_HY_ECDH_BIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l3-fo-sha384"), OQS_KEM_alg_bike1_l3_fo,
	SSH2_MSG_HY_ECDH_BIKE_INIT, SSH2_MSG_HY_ECDH_BIKE_REPLY},
#endif /* HAVE_BIKE */
#ifdef HAVE_FRODO
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-640-aes-sha384"), OQS_KEM_alg_frodokem_640_aes,
	SSH2_MSG_HY_ECDH_FRODO_INIT, SSH2_MSG_HY_ECDH_FRODO_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-640-shake-sha384"), OQS_KEM_alg_frodokem_640_shake,
	SSH2_MSG_HY_ECDH_FRODO_INIT, SSH2_MSG_HY_ECDH_FRODO_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-976-aes-sha384"), OQS_KEM_alg_frodokem_976_aes,
	SSH2_MSG_HY_ECDH_FRODO_INIT, SSH2_MSG_HY_ECDH_FRODO_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-976-shake-sha384"), OQS_KEM_alg_frodokem_976_shake,
	SSH2_MSG_HY_ECDH_FRODO_INIT, SSH2_MSG_HY_ECDH_FRODO_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-1344-aes-sha384"), OQS_KEM_alg_frodokem_1344_aes,
	SSH2_MSG_HY_ECDH_FRODO_INIT, SSH2_MSG_HY_ECDH_FRODO_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-1344-shake-sha384"), OQS_KEM_alg_frodokem_1344_shake,
	SSH2_MSG_HY_ECDH_FRODO_INIT, SSH2_MSG_HY_ECDH_FRODO_REPLY},
#endif /* HAVE_FRODO */
#ifdef HAVE_KYBER
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-512-sha384"), OQS_KEM_alg_kyber_512,
	SSH2_MSG_HY_ECDH_KYBER_INIT, SSH2_MSG_HY_ECDH_KYBER_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768-sha384"), OQS_KEM_alg_kyber_768,
	SSH2_MSG_HY_ECDH_KYBER_INIT, SSH2_MSG_HY_ECDH_KYBER_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-1024-sha384"), OQS_KEM_alg_kyber_1024,
	SSH2_MSG_HY_ECDH_KYBER_INIT, SSH2_MSG_HY_ECDH_KYBER_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-512-90s-sha384"), OQS_KEM_alg_kyber_512_90s,
	SSH2_MSG_HY_ECDH_KYBER_INIT, SSH2_MSG_HY_ECDH_KYBER_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768-90s-sha384"), OQS_KEM_alg_kyber_768_90s,
	SSH2_MSG_HY_ECDH_KYBER_INIT, SSH2_MSG_HY_ECDH_KYBER_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-1024-90s-sha384"), OQS_KEM_alg_kyber_1024_90s,
	SSH2_MSG_HY_ECDH_KYBER_INIT, SSH2_MSG_HY_ECDH_KYBER_REPLY},
#endif /* HAVE_KYBER */
#ifdef HAVE_NEWHOPE
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-newhope-512-sha384"), OQS_KEM_alg_newhope_512cca,
	SSH2_MSG_HY_ECDH_NEWHOPE_INIT, SSH2_MSG_HY_ECDH_NEWHOPE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-newhope-1024-sha384"), OQS_KEM_alg_newhope_1024cca,
	SSH2_MSG_HY_ECDH_NEWHOPE_INIT, SSH2_MSG_HY_ECDH_NEWHOPE_REPLY},
#endif /* HAVE_NEWHOPE */
#ifdef HAVE_NTRU
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-2048-509-sha384"), OQS_KEM_alg_ntru_hps2048509,
	SSH2_MSG_HY_ECDH_NTRU_INIT, SSH2_MSG_HY_ECDH_NTRU_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-2048-677-sha384"), OQS_KEM_alg_ntru_hps2048677,
	SSH2_MSG_HY_ECDH_NTRU_INIT, SSH2_MSG_HY_ECDH_NTRU_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hrss-701-sha384"), OQS_KEM_alg_ntru_hrss701,
	SSH2_MSG_HY_ECDH_NTRU_INIT, SSH2_MSG_HY_ECDH_NTRU_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-4096-821-sha384"), OQS_KEM_alg_ntru_hps4096821,
	SSH2_MSG_HY_ECDH_NTRU_INIT, SSH2_MSG_HY_ECDH_NTRU_REPLY},
#endif /* HAVE_NTRU */
#ifdef HAVE_SABER
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-lightsaber-sha384"), OQS_KEM_alg_saber_lightsaber,
	SSH2_MSG_HY_ECDH_SABER_INIT, SSH2_MSG_HY_ECDH_SABER_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-saber-sha384"), OQS_KEM_alg_saber_saber,
	SSH2_MSG_HY_ECDH_SABER_INIT, SSH2_MSG_HY_ECDH_SABER_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-firesaber-sha384"), OQS_KEM_alg_saber_firesaber,
	SSH2_MSG_HY_ECDH_SABER_INIT, SSH2_MSG_HY_ECDH_SABER_REPLY},
#endif /* HAVE_SABER */
#ifdef HAVE_SIDH
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p434-sha384"), OQS_KEM_alg_sidh_p434,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p503-sha384"), OQS_KEM_alg_sidh_p503,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p610-sha384"), OQS_KEM_alg_sidh_p610,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p751-sha384"), OQS_KEM_alg_sidh_p751,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p434-compressed-sha384"), OQS_KEM_alg_sidh_p434_compressed,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p503-compressed-sha384"), OQS_KEM_alg_sidh_p503_compressed,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p610-compressed-sha384"), OQS_KEM_alg_sidh_p610_compressed,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p751-compressed-sha384"), OQS_KEM_alg_sidh_p751_compressed,
	SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
#endif /* HAVE_SIDH */
#ifdef HAVE_SIKE
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p434-sha384"), OQS_KEM_alg_sike_p434,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p503-sha384"), OQS_KEM_alg_sike_p503,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p610-sha384"), OQS_KEM_alg_sike_p610,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p751-sha384"), OQS_KEM_alg_sike_p751,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p434-compressed-sha384"), OQS_KEM_alg_sike_p434_compressed,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p503-compressed-sha384"), OQS_KEM_alg_sike_p503_compressed,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p610-compressed-sha384"), OQS_KEM_alg_sike_p610_compressed,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p751-compressed-sha384"), OQS_KEM_alg_sike_p751_compressed,
	SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
#endif /* HAVE_SIKE */
#ifdef HAVE_THREEBEARS
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-babybear-sha384"), OQS_KEM_alg_threebears_babybear,
	SSH2_MSG_HY_ECDH_THREEBEARS_INIT, SSH2_MSG_HY_ECDH_THREEBEARS_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-babybear-ephem-sha384"), OQS_KEM_alg_threebears_babybear_ephem,
	SSH2_MSG_HY_ECDH_THREEBEARS_INIT, SSH2_MSG_HY_ECDH_THREEBEARS_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-mamabear-sha384"), OQS_KEM_alg_threebears_mamabear,
	SSH2_MSG_HY_ECDH_THREEBEARS_INIT, SSH2_MSG_HY_ECDH_THREEBEARS_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-mamabear-ephem-sha384"), OQS_KEM_alg_threebears_mamabear_ephem,
	SSH2_MSG_HY_ECDH_THREEBEARS_INIT, SSH2_MSG_HY_ECDH_THREEBEARS_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-papabear-sha384"), OQS_KEM_alg_threebears_papabear,
	SSH2_MSG_HY_ECDH_THREEBEARS_INIT, SSH2_MSG_HY_ECDH_THREEBEARS_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-papabear-ephem-sha384"), OQS_KEM_alg_threebears_papabear_ephem,
	SSH2_MSG_HY_ECDH_THREEBEARS_INIT, SSH2_MSG_HY_ECDH_THREEBEARS_REPLY},
#endif /* HAVE_THREEBEARS */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_END
#endif /* defined(OPENSSL_HAS_ECC) && defined(WITH_HYBRID_KEX) */
/* PQ-only key exchange methods */
#ifdef WITH_PQ_KEX
	{PQ_OQS_KEX_SUFFIX("oqsdefault-sha384"), OQS_KEM_alg_default,
	SSH2_MSG_PQ_OQSDEFAULT_INIT, SSH2_MSG_PQ_OQSDEFAULT_REPLY},
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_START
#ifdef HAVE_BIKE
	{PQ_OQS_KEX_SUFFIX("bike1-l1-cpa-sha384"), OQS_KEM_alg_bike1_l1_cpa,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-l3-cpa-sha384"), OQS_KEM_alg_bike1_l3_cpa,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-l1-fo-sha384"), OQS_KEM_alg_bike1_l1_fo,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-l3-fo-sha384"), OQS_KEM_alg_bike1_l3_fo,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
#endif /* HAVE_BIKE */
#ifdef HAVE_FRODO
	{PQ_OQS_KEX_SUFFIX("frodo-640-aes-sha384"), OQS_KEM_alg_frodokem_640_aes,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-640-shake-sha384"), OQS_KEM_alg_frodokem_640_shake,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-976-aes-sha384"), OQS_KEM_alg_frodokem_976_aes,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-976-shake-sha384"), OQS_KEM_alg_frodokem_976_shake,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-1344-aes-sha384"), OQS_KEM_alg_frodokem_1344_aes,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-1344-shake-sha384"), OQS_KEM_alg_frodokem_1344_shake,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
#endif /* HAVE_FRODO */
#ifdef HAVE_KYBER
	{PQ_OQS_KEX_SUFFIX("kyber-512-sha384"), OQS_KEM_alg_kyber_512,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-768-sha384"), OQS_KEM_alg_kyber_768,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-1024-sha384"), OQS_KEM_alg_kyber_1024,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-512-90s-sha384"), OQS_KEM_alg_kyber_512_90s,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-768-90s-sha384"), OQS_KEM_alg_kyber_768_90s,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-1024-90s-sha384"), OQS_KEM_alg_kyber_1024_90s,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
#endif /* HAVE_KYBER */
#ifdef HAVE_NEWHOPE
	{PQ_OQS_KEX_SUFFIX("newhope-512-sha384"), OQS_KEM_alg_newhope_512cca,
	SSH2_MSG_PQ_NEWHOPE_INIT, SSH2_MSG_PQ_NEWHOPE_REPLY},
	{PQ_OQS_KEX_SUFFIX("newhope-1024-sha384"), OQS_KEM_alg_newhope_1024cca,
	SSH2_MSG_PQ_NEWHOPE_INIT, SSH2_MSG_PQ_NEWHOPE_REPLY},
#endif /* HAVE_NEWHOPE */
#ifdef HAVE_NTRU
	{PQ_OQS_KEX_SUFFIX("ntru-hps-2048-509-sha384"), OQS_KEM_alg_ntru_hps2048509,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
	{PQ_OQS_KEX_SUFFIX("ntru-hps-2048-677-sha384"), OQS_KEM_alg_ntru_hps2048677,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
	{PQ_OQS_KEX_SUFFIX("ntru-hrss-701-sha384"), OQS_KEM_alg_ntru_hrss701,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
	{PQ_OQS_KEX_SUFFIX("ntru-hps-4096-821-sha384"), OQS_KEM_alg_ntru_hps4096821,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
#endif /* HAVE_NTRU */
#ifdef HAVE_SABER
	{PQ_OQS_KEX_SUFFIX("saber-lightsaber-sha384"), OQS_KEM_alg_saber_lightsaber,
	SSH2_MSG_PQ_SABER_INIT, SSH2_MSG_PQ_SABER_REPLY},
	{PQ_OQS_KEX_SUFFIX("saber-saber-sha384"), OQS_KEM_alg_saber_saber,
	SSH2_MSG_PQ_SABER_INIT, SSH2_MSG_PQ_SABER_REPLY},
	{PQ_OQS_KEX_SUFFIX("saber-firesaber-sha384"), OQS_KEM_alg_saber_firesaber,
	SSH2_MSG_PQ_SABER_INIT, SSH2_MSG_PQ_SABER_REPLY},
#endif /* HAVE_SABER */
#ifdef HAVE_SIDH
	{PQ_OQS_KEX_SUFFIX("sidh-p434-sha384"), OQS_KEM_alg_sidh_p434,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p503-sha384"), OQS_KEM_alg_sidh_p503,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p610-sha384"), OQS_KEM_alg_sidh_p610,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p751-sha384"), OQS_KEM_alg_sidh_p751,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p434-compressed-sha384"), OQS_KEM_alg_sidh_p434_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p503-compressed-sha384"), OQS_KEM_alg_sidh_p503_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p610-compressed-sha384"), OQS_KEM_alg_sidh_p610_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p751-compressed-sha384"), OQS_KEM_alg_sidh_p751_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
#endif /* HAVE_SIDH */
#ifdef HAVE_SIKE
	{PQ_OQS_KEX_SUFFIX("sike-p434-sha384"), OQS_KEM_alg_sike_p434,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p503-sha384"), OQS_KEM_alg_sike_p503,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p610-sha384"), OQS_KEM_alg_sike_p610,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p751-sha384"), OQS_KEM_alg_sike_p751,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p434-compressed-sha384"), OQS_KEM_alg_sike_p434_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p503-compressed-sha384"), OQS_KEM_alg_sike_p503_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p610-compressed-sha384"), OQS_KEM_alg_sike_p610_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p751-compressed-sha384"), OQS_KEM_alg_sike_p751_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
#endif /* HAVE_SIKE */
#ifdef HAVE_THREEBEARS
	{PQ_OQS_KEX_SUFFIX("babybear-sha384"), OQS_KEM_alg_threebears_babybear,
	SSH2_MSG_PQ_THREEBEARS_INIT, SSH2_MSG_PQ_THREEBEARS_REPLY},
	{PQ_OQS_KEX_SUFFIX("babybear-ephem-sha384"), OQS_KEM_alg_threebears_babybear_ephem,
	SSH2_MSG_PQ_THREEBEARS_INIT, SSH2_MSG_PQ_THREEBEARS_REPLY},
	{PQ_OQS_KEX_SUFFIX("mamabear-sha384"), OQS_KEM_alg_threebears_mamabear,
	SSH2_MSG_PQ_THREEBEARS_INIT, SSH2_MSG_PQ_THREEBEARS_REPLY},
	{PQ_OQS_KEX_SUFFIX("mamabear-ephem-sha384"), OQS_KEM_alg_threebears_mamabear_ephem,
	SSH2_MSG_PQ_THREEBEARS_INIT, SSH2_MSG_PQ_THREEBEARS_REPLY},
	{PQ_OQS_KEX_SUFFIX("papabear-sha384"), OQS_KEM_alg_threebears_papabear,
	SSH2_MSG_PQ_THREEBEARS_INIT, SSH2_MSG_PQ_THREEBEARS_REPLY},
	{PQ_OQS_KEX_SUFFIX("papabear-ephem-sha384"), OQS_KEM_alg_threebears_papabear_ephem,
	SSH2_MSG_PQ_THREEBEARS_INIT, SSH2_MSG_PQ_THREEBEARS_REPLY},
#endif /* HAVE_THREEBEARS */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_END
#endif /* WITH_PQ_KEX */
	{NULL,NULL,0,0} /* End of list */
};

/*
 * @brief Maps the named SSH key exchange method's PQ kex algorithm
 * to liboqs key exchange algorithm
 */
const OQS_ALG *
oqs_mapping(const char *ssh_kex_name) {

	const OQS_ALG *alg = NULL;

	for (alg = oqs_alg_mapping; alg->kex_alg != NULL; alg++) {
		if (strcmp(alg->kex_alg, ssh_kex_name) == 0) {
			return alg;
		}
	}

	return NULL;
}

/*
 * @brief Initialise key exchange liboqs specific context
 */
int
oqs_init(OQS_KEX_CTX **oqs_kex_ctx, char *ssh_kex_name) {

	OQS_KEX_CTX *tmp_oqs_kex_ctx = NULL;
	const OQS_ALG *oqs_alg = NULL;
	int r = 0;

	if ((tmp_oqs_kex_ctx = calloc(sizeof(*(tmp_oqs_kex_ctx)), 1)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((oqs_alg = oqs_mapping(ssh_kex_name)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	tmp_oqs_kex_ctx->oqs_kem = NULL;
	tmp_oqs_kex_ctx->oqs_method = strdup(oqs_alg->alg_name);
	tmp_oqs_kex_ctx->oqs_local_priv = NULL;
	tmp_oqs_kex_ctx->oqs_local_priv_len = 0;
	tmp_oqs_kex_ctx->oqs_local_msg = NULL;
	tmp_oqs_kex_ctx->oqs_local_msg_len = 0;
	tmp_oqs_kex_ctx->oqs_remote_msg = NULL;
	tmp_oqs_kex_ctx->oqs_remote_msg_len = 0;

	/* Use PRNG provided by OpenSSH instad of liboqs's PRNG */
	OQS_randombytes_custom_algorithm((void (*)(uint8_t *, size_t)) &arc4random_buf);

	*oqs_kex_ctx = tmp_oqs_kex_ctx;
	tmp_oqs_kex_ctx = NULL;

out:
	if (tmp_oqs_kex_ctx != NULL)
		free(tmp_oqs_kex_ctx);

	return r;
}

/*
 * @brief Free memory allocated for oqs part of key exchange
 */
void
oqs_free(OQS_KEX_CTX *oqs_kex_ctx) {

	if (oqs_kex_ctx->oqs_local_msg != NULL) {
		free(oqs_kex_ctx->oqs_local_msg);
		oqs_kex_ctx->oqs_local_msg = NULL;
	}
	if (oqs_kex_ctx->oqs_remote_msg != NULL) {
		free(oqs_kex_ctx->oqs_remote_msg);
		oqs_kex_ctx->oqs_remote_msg = NULL;
	}
	if (oqs_kex_ctx->oqs_local_priv != NULL) {
		explicit_bzero(oqs_kex_ctx->oqs_local_priv, oqs_kex_ctx->oqs_local_priv_len);
		free(oqs_kex_ctx->oqs_local_priv);
		oqs_kex_ctx->oqs_local_priv = NULL;
	}
	if (oqs_kex_ctx->oqs_method != NULL) {
		free(oqs_kex_ctx->oqs_method);
		oqs_kex_ctx->oqs_method = NULL;
	}
	if (oqs_kex_ctx->oqs_kem != NULL) {
		OQS_KEM_free(oqs_kex_ctx->oqs_kem);
		oqs_kex_ctx->oqs_kem = NULL;
	}
}

/*
 * @brief SSH hybrid key exchange init message name
 */
int
oqs_ssh2_init_msg(const OQS_ALG *oqs_alg) {
	return oqs_alg->ssh2_init_msg;
}

/*
 * @brief SSH hybrid key exchange reply message name
 */
int
oqs_ssh2_reply_msg(const OQS_ALG *oqs_alg) {
	return oqs_alg->ssh2_reply_msg;
}

/*
 * @brief Generates the client side part of the liboqs kex
 */
int
oqs_client_gen(OQS_KEX_CTX *oqs_kex_ctx) {

	OQS_KEM *oqs_kem = NULL;
	int r = 0;

	if ((oqs_kem = OQS_KEM_new(oqs_kex_ctx->oqs_method)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	oqs_kex_ctx->oqs_local_priv = NULL;
	oqs_kex_ctx->oqs_local_msg = NULL;

	oqs_kex_ctx->oqs_local_priv_len = oqs_kem->length_secret_key;
	if ((oqs_kex_ctx->oqs_local_priv = malloc(oqs_kem->length_secret_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	oqs_kex_ctx->oqs_local_msg_len = oqs_kem->length_public_key;
	if ((oqs_kex_ctx->oqs_local_msg = malloc(oqs_kem->length_public_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* Generate client side part of kex */
	if (OQS_KEM_keypair(oqs_kem, oqs_kex_ctx->oqs_local_msg,
		oqs_kex_ctx->oqs_local_priv) != OQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	oqs_kex_ctx->oqs_kem = oqs_kem;
	oqs_kem = NULL;

out:
	if (oqs_kem != NULL) {
		OQS_KEM_free(oqs_kem);
		free(oqs_kex_ctx->oqs_local_priv);
		free(oqs_kex_ctx->oqs_local_msg);
	}

	return r;
}

/*
 * @brief Deserialise liboqs specific parts of incoming packet
 */
int
oqs_deserialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	enum oqs_client_or_server client_or_server) {

	return sshpkt_get_string(ssh, &(oqs_kex_ctx->oqs_remote_msg),
		&(oqs_kex_ctx->oqs_remote_msg_len));
}

/*
 * @brief Serialise liboqs specific parts of outgoing packet
 */
int
oqs_serialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	enum oqs_client_or_server client_or_server) {

	return sshpkt_put_string(ssh, oqs_kex_ctx->oqs_local_msg,
		oqs_kex_ctx->oqs_local_msg_len);
}

/*
 * @brief Generates liboqs kex shared secret
 */
int
oqs_client_shared_secret(OQS_KEX_CTX *oqs_kex_ctx,
	u_char **oqs_shared_secret, size_t *oqs_shared_secret_len) {

	uint8_t *tmp_oqs_shared_secret = NULL;
	int r = 0;

	if (oqs_kex_ctx->oqs_remote_msg_len != oqs_kex_ctx->oqs_kem->length_ciphertext) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((tmp_oqs_shared_secret = malloc(oqs_kex_ctx->oqs_kem->length_shared_secret)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* Generate shared secret from client private key and server public key */
	if (OQS_KEM_decaps(oqs_kex_ctx->oqs_kem, tmp_oqs_shared_secret,
		oqs_kex_ctx->oqs_remote_msg, oqs_kex_ctx->oqs_local_priv) != OQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	*oqs_shared_secret = (u_char *) tmp_oqs_shared_secret;
	*oqs_shared_secret_len = oqs_kex_ctx->oqs_kem->length_shared_secret;

	tmp_oqs_shared_secret = NULL;

out:
	if (tmp_oqs_shared_secret != NULL) {
		explicit_bzero(tmp_oqs_shared_secret, oqs_kex_ctx->oqs_kem->length_shared_secret);
		free(tmp_oqs_shared_secret);
	}

	return r;
}

/*
 * @brief Generates server message and, simultanously generates
 * the shared secret from server private key and client public key
 */
int
oqs_server_gen_msg_and_ss(OQS_KEX_CTX *oqs_kex_ctx,
	u_char **oqs_shared_secret, size_t *oqs_shared_secret_len) {

	OQS_KEM *oqs_kem = NULL;
	uint8_t *tmp_oqs_shared_secret = NULL, *tmp_oqs_local_msg = NULL;
	int r = 0;

	if ((oqs_kem = OQS_KEM_new(oqs_kex_ctx->oqs_method)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if (oqs_kex_ctx->oqs_remote_msg_len != oqs_kem->length_public_key) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((tmp_oqs_local_msg = malloc(oqs_kem->length_ciphertext)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((tmp_oqs_shared_secret = malloc(oqs_kem->length_shared_secret)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (OQS_KEM_encaps(oqs_kem, tmp_oqs_local_msg, tmp_oqs_shared_secret,
		oqs_kex_ctx->oqs_remote_msg) != OQS_SUCCESS) {
				r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	*oqs_shared_secret = (u_char *) tmp_oqs_shared_secret;
	*oqs_shared_secret_len = oqs_kem->length_shared_secret;
	oqs_kex_ctx->oqs_local_msg = tmp_oqs_local_msg;
	oqs_kex_ctx->oqs_local_msg_len = oqs_kem->length_ciphertext;

	tmp_oqs_shared_secret = NULL;

out:
	if (oqs_kem != NULL) {
		OQS_KEM_free(oqs_kem);
	}
	if (tmp_oqs_shared_secret != NULL) {
		explicit_bzero(tmp_oqs_shared_secret, oqs_kem->length_shared_secret);
		free(tmp_oqs_shared_secret);
		free(tmp_oqs_local_msg);
	}

	return r;
}

#endif /* WITH_OQS */
