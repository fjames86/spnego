
/** this does an internal negotiation to inspect what the generated buffers are. */

#define SECURITY_WIN32
#define BIG_BUFF   2048
#define SEC_SUCCESS(Status) ((Status) >= 0)
#define g_usPort 2000

#define cbMaxMessage 12000
#define MessageAttribute ISC_REQ_CONFIDENTIALITY 

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Sspi.h>
#include <ws2tcpip.h>

#define BUFF_SIZE 8096

int main( int argc, char **argv ) {
	CredHandle cred, server_cred;
	TimeStamp lifetime;
	SECURITY_STATUS sts;
	char buffer[BUFF_SIZE], server_buffer[BUFF_SIZE];
	struct _SecHandle hsec, server_hsec;
	SecBufferDesc input, output, server_output;
	SecBuffer inputbuff, outputbuff, server_outputbuff;
	ULONG attrs;
	int i;

	// initalize security context 
	//sts = AcquireCredentialsHandleA ( NULL, "Kerberos", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &cred, &lifetime );
	sts = AcquireCredentialsHandleA ( NULL, "Negotiate", SECPKG_CRED_BOTH, NULL, NULL, NULL, NULL, &cred, &lifetime );
	//sts = AcquireCredentialsHandleA ( NULL, "NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &cred, &lifetime );
	
	if( sts ) {
		printf( "Bad thing\n" );
		abort();
	}
	
	SEC_E_TARGET_UNKNOWN;

	// setup
	output.ulVersion = 0;
	output.cBuffers = 1;
	output.pBuffers = &outputbuff;
	outputbuff.cbBuffer = BUFF_SIZE;
	outputbuff.BufferType = SECBUFFER_TOKEN;
	outputbuff.pvBuffer = buffer;

	// get a thing
	//sts = InitializeSecurityContextA ( &cred, &hsec, "Administrator", MessageAttribute, 0, SECURITY_NATIVE_DREP, &input, 0, &hsec, &output, &attrs, &lifetime );
	sts = InitializeSecurityContextA ( &cred, NULL, "HTTP/myhostname@DOMAIN.COM", MessageAttribute, 0, SECURITY_NATIVE_DREP, 
										NULL, 0, &hsec, &output, &attrs, &lifetime );
	if( sts == SEC_I_CONTINUE_NEEDED ) {
		printf( "Continue needed\n" );
	} else if( sts == SEC_I_RENEGOTIATE ) {
		printf( "Renegotiate\n" );
	} else if( sts ) {
		printf( "bad thing: %x\n", sts );
		abort();
	}

#if 0
	i = 0;
	while( i < output.pBuffers->cbBuffer )  {
		int j;

		printf( "%08x: ", i );

		for( j = 0; j < 16; j++ ) {
			if( (i + j) < output.pBuffers->cbBuffer ) {
				unsigned char x = ((unsigned char *)(output.pBuffers->pvBuffer))[i + j];
				printf( "%02x ", x );
			} else {
				printf( "   " );
			}
		}

		printf( " | " );
		for( j = 0; j < 16; j++ ) {
			if( (i + j) < output.pBuffers->cbBuffer ) {
				unsigned char x = ((unsigned char *)(output.pBuffers->pvBuffer))[i + j];
				if( isprint( x ) ) printf( "%c", x );
				else printf( "." );
			}
		}
		
		printf( "\n" );

		i += 16;
	}
#else
	for( i = 0; i < output.pBuffers->cbBuffer; i++ ) {
		unsigned char x = ((unsigned char *)(output.pBuffers->pvBuffer))[i];
		printf( "%2u ", x );
		if( i && (i % 16) == 0 ) printf( "\n" );
	}
	printf( "\n" );
#endif

	// server accepts the context
	//sts = AcquireCredentialsHandleA ( NULL, "Kerberos", SECPKG_CRED_BOTH, NULL, NULL, NULL, NULL, &server_cred, &lifetime );
	sts = AcquireCredentialsHandleA ( NULL, "Negotiate", SECPKG_CRED_BOTH, NULL, NULL, NULL, NULL, &server_cred, &lifetime );
	//sts = AcquireCredentialsHandleA ( NULL, "NTLM", SECPKG_CRED_BOTH, NULL, NULL, NULL, NULL, &server_cred, &lifetime );
	
	server_output.ulVersion = 0;
	server_output.cBuffers = 1;
	server_output.pBuffers = &server_outputbuff;
	server_outputbuff.cbBuffer = BUFF_SIZE;
	server_outputbuff.BufferType = SECBUFFER_TOKEN;
	server_outputbuff.pvBuffer = server_buffer;
	sts = AcceptSecurityContext( &server_cred, NULL, &output, 0, SECURITY_NATIVE_DREP, &server_hsec, &server_output,	
									&attrs, &lifetime );
	if( sts == SEC_I_CONTINUE_NEEDED ) {
		printf( "Continue needed\n" );
	} else if( sts == SEC_I_RENEGOTIATE ) {
		printf( "Renegotiate\n" );	
	} else if( sts ) {
		printf( "bad thing: %x\n", sts );
		abort();
	}

	for( i = 0; i < server_output.pBuffers->cbBuffer; i++ ) {
		unsigned char x = ((unsigned char *)(server_output.pBuffers->pvBuffer))[i];
		printf( "%2u ", x );
		if( i && (i % 16) == 0 ) printf( "\n" );
	}
	printf( "\n" );

	// back to the client
	output.ulVersion = 0;
	output.cBuffers = 1;
	output.pBuffers = &outputbuff;
	outputbuff.cbBuffer = BUFF_SIZE;
	outputbuff.BufferType = SECBUFFER_TOKEN;
	outputbuff.pvBuffer = buffer;
	sts = InitializeSecurityContextA ( &cred, &hsec, "HTTP/myhostname@DOMAIN.COM", MessageAttribute, 0, SECURITY_NATIVE_DREP, 
										&server_output, 0, &hsec, &output, &attrs, &lifetime );
	if( sts == SEC_I_CONTINUE_NEEDED ) {
		printf( "Continue needed\n" );
	} else if( sts == SEC_I_RENEGOTIATE ) {
		printf( "Renegotiate\n" );	
	} else if( sts ) {
		printf( "bad thing: %x\n", sts );
		abort();
	}
	for( i = 0; i < output.pBuffers->cbBuffer; i++ ) {
		unsigned char x = ((unsigned char *)(output.pBuffers->pvBuffer))[i];
		printf( "%2u ", x );
		if( i && (i % 16) == 0 ) printf( "\n" );
	}
	printf( "\n" );




	// back to the server 
	server_output.ulVersion = 0;
	server_output.cBuffers = 1;
	server_output.pBuffers = &outputbuff;
	server_outputbuff.cbBuffer = BUFF_SIZE;
	server_outputbuff.BufferType = SECBUFFER_TOKEN;
	server_outputbuff.pvBuffer = server_buffer;
	sts = AcceptSecurityContext( &server_cred, &server_hsec, &output, 0, SECURITY_NATIVE_DREP, &server_hsec, 
									&server_output, &attrs, &lifetime );
	if( sts == SEC_I_CONTINUE_NEEDED ) {
		printf( "Continue needed\n" );
	} else if( sts == SEC_I_RENEGOTIATE ) {
		printf( "Renegotiate\n" );	
	} else if( sts ) {
		printf( "bad thing: %x\n", sts );
		abort();
	}

	for( i = 0; i < server_output.pBuffers->cbBuffer; i++ ) {
		unsigned char x = ((unsigned char *)(server_output.pBuffers->pvBuffer))[i];
		printf( "%2u ", x );
		if( i && (i % 16) == 0 ) printf( "\n" );
	}
	printf( "\n" );

	return 0;
}


