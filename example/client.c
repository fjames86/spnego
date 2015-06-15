
/**
 * This defines an HTTP client which uses SPNEGO (Negotiate) authentication.
 * Point it at the HTTP server (defined in server.lisp).
 * 
 */

#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>
#include <Ntdsapi.h>

#define MY_USERNAME "frank"
#define MY_PASSWORD "james"
#define USE_BASIC_AUTH 0
#define USE_NTLM_AUTH 0
#define USE_KRB_AUTH 1

static void send_http_request( HANDLE hsession, char *url );

void dowork( void ) {
	HANDLE hsession = WinHttpOpen( L"frankclient",
						 WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
						 WINHTTP_NO_PROXY_NAME,
						 WINHTTP_NO_PROXY_BYPASS,
						 0 );
	send_http_request( hsession, "http://localhost:2001" );

	WinHttpCloseHandle( hsession );
}


static void send_http_request( HANDLE hsession, char *url ) {
	HINTERNET hconn = NULL, hreq = NULL;
	DWORD d, n, size;
	BOOL res;
	wchar_t wbuff[1024];
	URL_COMPONENTS uc;
	wchar_t hostname[255], scheme[32], urlpath[255], extra[255];
	wchar_t wuser[256], wpass[256];
	BOOL use_ssl = FALSE;
	char *buff;
	char buffer[1024];
	DWORD nbytes;
	//static wchar_t *reqtypes[] = { L"text/xml", NULL };
	//static wchar_t *reqheaders = L"Content-Type: text/xml\r\n";
	static wchar_t *http_method[] = { L"GET", L"POST", L"PUT", L"DELETE" };

	// convert the url to wchar
	mbstowcs( wbuff, url, 1024 );

	// get length
	d = (DWORD)wcslen( wbuff );

	// setup the url components structure and parse it 
	memset( &uc, 0, sizeof(uc) );
    uc.dwStructSize = sizeof (uc);
    uc.lpszScheme = scheme;
    uc.dwSchemeLength = 32;
    uc.lpszHostName = hostname; 
    uc.dwHostNameLength  = 255;
    uc.lpszUrlPath  = urlpath; 
    uc.dwUrlPathLength   = 255;
    uc.lpszExtraInfo     = extra;
    uc.dwExtraInfoLength = 255;
	res = WinHttpCrackUrl( wbuff, d, ICU_ESCAPE, &uc );

	// use ssl if set to https
	if( _wcsicmp( scheme, L"https" ) == 0 ) use_ssl = TRUE;
	
	// if no port specified then use the appropriate default 
	if( !uc.nPort ) {
		uc.nPort = (use_ssl ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);
	}

	// FIXME: we should really only create one of these per client, i.e. in jrc_client_init
	// WinHttpConnect needs the host name in wide char format
	hconn = WinHttpConnect( hsession, hostname, uc.nPort, 0 );

	d = (use_ssl ? WINHTTP_FLAG_SECURE : 0);
	hreq = WinHttpOpenRequest( hconn, L"GET",
								urlpath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, //reqtypes
								d );

	// clear out the header buffer (FIXME: possible buffer overflow - use sprintf_s instead)
	wcscpy( wbuff, L"" );
	// add the content-type header to say it's json
	// FIXME: also add "; charset=UTF-8" ? this is sometimes needed
	wcscat( wbuff, L"Content-Type: application/json");

	res = WinHttpAddRequestHeaders( hreq, wbuff, -1, WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE );

	// set credentials
	if( USE_BASIC_AUTH ) {
		mbstowcs( wuser, MY_USERNAME, 256 );
		mbstowcs( wpass, MY_PASSWORD, 256 );
		res = WinHttpSetCredentials( hreq, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_BASIC, wuser, wpass, NULL );
	} else if( USE_NTLM_AUTH ) {
		// if no creds provided use auto logon
		if( MY_USERNAME[0] && MY_PASSWORD[0] ) {
			mbstowcs( wuser, MY_USERNAME, 256 );
			mbstowcs( wpass, MY_PASSWORD, 256 );
			res = WinHttpSetCredentials( hreq, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_NTLM, wuser, wpass, NULL );
		} else {
			// set to use auto logon, the security level must be low 
			// if the level is not set to low then you can get authentication failure 
			d = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
			res = WinHttpSetOption( hreq, WINHTTP_OPTION_AUTOLOGON_POLICY, &d, sizeof(d) );

			res = WinHttpSetCredentials( hreq, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_NTLM, NULL, NULL, NULL );
		}
	} else if( USE_KRB_AUTH ) {
		res = WinHttpSetCredentials( hreq, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_NEGOTIATE, NULL, NULL, NULL );
	}

	// set options
	if( 1 ) {
		d = SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		res = WinHttpSetOption( hreq, WINHTTP_OPTION_SECURITY_FLAGS, &d, sizeof(d) );
	}

	// set the timeout to infinity
	 d = INFINITE;
	res = WinHttpSetOption( hreq, WINHTTP_OPTION_CONNECT_TIMEOUT, &d, sizeof(d) );


	// send the request
	res = WinHttpSendRequest( hreq, 
							WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
							"hello", 5,
							5, 0 );

	// recveive the response 
	res = WinHttpReceiveResponse( hreq, NULL );

	// FIXME: retrieve the response headers and tell the caller about them somehow
	// check the status 
	d = sizeof(n);
	res = WinHttpQueryHeaders( hreq, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &n, &d, WINHTTP_NO_HEADER_INDEX );

	if( n != 200 ) {
		DWORD supported, first, target;

		d = sizeof(wbuff);		
		res = WinHttpQueryHeaders( hreq, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, wbuff, &d, WINHTTP_NO_HEADER_INDEX );
		if( res ) wprintf( L"headers: %s\n", wbuff );

		d = sizeof(wbuff);		
		memset( wbuff, 0, sizeof(wbuff) );
		res = WinHttpQueryHeaders( hreq, WINHTTP_QUERY_AUTHENTICATION_INFO, WINHTTP_HEADER_NAME_BY_INDEX, wbuff, &d, WINHTTP_NO_HEADER_INDEX );
		if( res ) wprintf( L"authorization: %s\n", wbuff );
		else {
			res = GetLastError();
			printf( "Failed to get auth data: %x (%d)\n", res, res );
		}

		res = WinHttpQueryAuthSchemes( hreq, &supported, &first, &target );
		if( !res ) {
			res = GetLastError();
			switch( res ) {
			case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
				printf( "Incorrect handle\n" );
				break;
			case ERROR_WINHTTP_INTERNAL_ERROR:
				printf( "Internal error\n" );
				break;
			case ERROR_NOT_ENOUGH_MEMORY:
				printf( "Not enough memory\n" );
				break;
			default:
				printf( "Error %x (%d)\n", res, res );
			};
		}

		res = WinHttpSetCredentials( hreq, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_NEGOTIATE, NULL, NULL, NULL );
		res = WinHttpSendRequest( hreq, 
							WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
							"hello", 5,
							5, 0 );
		res = WinHttpReceiveResponse( hreq, NULL );
		d = sizeof(n);
		res = WinHttpQueryHeaders( hreq, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &n, &d, WINHTTP_NO_HEADER_INDEX );

		goto done;
	} else {
		// authenticdated
		memset( buffer, 0, sizeof(buffer) );
		res = WinHttpReadData( hreq, buffer, sizeof(buffer), &nbytes );
		if( !res ) {
			res = GetLastError();
			printf( "Failed to read data: %x (%d)\n", res, res );
		} else {
			printf( "Data:\n%s\n", buffer );
		}
	}

done:

	if( hreq ) WinHttpCloseHandle( hreq );
	if( hconn ) WinHttpCloseHandle( hconn );

	return;
}

int main( int argc, char **argv ) {
	DWORD count, res;
	char **buffer;
	
	


	dowork();
	return 0;
}

