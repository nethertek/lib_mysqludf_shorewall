/* 
	lib_mysqludf_shorewall - a library to generate Shorewall macros
							 and reload firewall rules via systemd (dbus)

	Copyright (C) 2016 NetherTek Engineering Innovations

	web: http://www.nethertek.net
	email: info@nethertek.net

	adapted string replace function by jmucchiello

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

	Compile with (adapt the include and lib path to your environment):
	> gcc -Wall -O2 lib_mysqludf_shorewall.c \
		-I/usr/include/mysql \
		-I/usr/include/dbus-1.0
		-I/usr/lib64/dbus-1.0/include/	
		-shared -fPIC -o lib_mysqludf_shorewall.so
	> strip ./lib_mysqludf_shorewall.so
	
	Add the functions to MySQL with:
	mysql> CREATE FUNCTION shorewall RETURNS STRING SONAME "lib_mysqludf_shorewall.so";

	Create the corresponding MySQL trigger (add another UPDATE trigger if required):

	The function takes 5 parameters:
		- Hostname of machine to execute changes on
		  (if the hostname does not match, processing stops)
		- Macro name for the shorewall rule
		- A valid IPv4 or IPv6 address
		- Enabled field, must be 1 to add rule, 0 removes rule
		- String to write to macro, :address will be replaced with IP address

	DELIMITER $$

	DROP TRIGGER IF EXISTS example.address_insert$$
	USE `example`$$
	CREATE DEFINER=`root`@`localhost` TRIGGER address_insert AFTER INSERT ON example.addresses
	FOR EACH ROW 
	  BEGIN 
	  set @rv = shorewall('myhost.example.com',
						  'MyMACRO',
						  NEW.`address_ip`,
						  NEW.`address_enabled`,
						  'PARAM\t:address\t-\ttcp\t8080\n');
	  END$$
	DELIMITER ;

	Add a shorewall rule to shorewall and/or shorewall6:
	MyMACRO(ACCEPT)		net		$FW

	Finally add a policy kit rule to /etc/polkit-1/rules.d/60-mysql.rules:
	polkit.addRule(function(action, subject) {
		if (action.id == "org.freedesktop.systemd1.manage-units" &&
			subject.user == "mysql") {
			return polkit.Result.YES;
		} });

	If everything is correct, it should now update and reload shorewall when
	changes are committed to the database. Don't forget to allow MySQL to write
	the macro file in the Shorewall directory. Tested on RHEL7 and compatible 
	distributions.
*/

#define DLLEXP

#ifdef STANDARD
/* STANDARD is defined, don't use any mysql functions */
#include <stdlib.h>
#include <string.h>

typedef unsigned long long ulonglong;
typedef long long longlong;

#else
#include <my_global.h>
#include <my_sys.h>
#include <m_string.h>
#endif
#include <mysql.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <dbus/dbus.h>

#ifdef HAVE_DLOPEN

#define LIBVERSION "lib_mysqludf_shorewall version 0.1.0"

/******************************************************************************
** function declarations
******************************************************************************/
#ifdef	__cplusplus
extern "C" {
#endif

DLLEXP 
my_bool shorewall_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
DLLEXP 
void shorewall_deinit(UDF_INIT *initid);
DLLEXP 
char *shorewall(UDF_INIT *initid, UDF_ARGS *args, char *result,
		unsigned long *res_length, char *null_value, char *error);

static DBusConnection *dbus = NULL;
static DBusError err;

#ifdef __cplusplus
}
#endif
// ------------------------------------------------------------------------------

my_bool shorewall_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{

	/* make sure user has provided exactly three string arguments */
	if (args->arg_count != 5 || (args->arg_type[0] != STRING_RESULT)
			 	 || (args->arg_type[1] != STRING_RESULT)
				 || (args->arg_type[2] != STRING_RESULT)
				 || (args->arg_type[3] != STRING_RESULT)
				 || (args->arg_type[4] != STRING_RESULT)){
		strcpy(message, "shorewall requires 5 string arguments");
		return 1;
	}

	if ((args->lengths[0] == 0) || (args->lengths[1] == 0) || (args->lengths[2] == 0) || (args->lengths[3] == 0) || (args->lengths[4] == 0)){
		strcpy(message, "shorewall arguments can not be empty");
		return 1;
	}
	
	// Establish DBUS connection
	dbus_error_init(&err);

	dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

	if (dbus_error_is_set(&err))
	{
		strcpy(message, "shorewall unable to connect to dbus");
		dbus_error_free(&err);
		return 2;
	}
	else
	{
		dbus_bus_register(dbus, &err);

		if (dbus_error_is_set(&err))
		{
			strcpy(message, "shorewall unable to register with dbus");
			dbus_error_free(&err);
			return 3;
		}
	}

	initid->maybe_null=0;

	return 0;
}

void shorewall_deinit(UDF_INIT *initid __attribute__((unused)))
{
} 

/******************************************************************************/

char *str_replace(char *orig, char *rep, char *with)
{
	char *result, *ins, *tmp;
	size_t len_rep, len_with, len_front, cnt;

	// sanity checks and initialization
	if (!orig && !rep)
		return NULL;

	len_rep = strlen(rep);

	if (len_rep == 0)
		return NULL; // empty rep causes infinite loop during count

	if (!with)
		with = "";

	len_with = strlen(with);

	// count the number of replacements needed
	ins = orig;
	for (cnt = 0; (tmp = strstr(ins, rep)); ++cnt) {
		ins = tmp + len_rep;
	}

	tmp = result = malloc(strlen(orig) + (len_with - len_rep) * cnt + 1);

	if (!result)
		return NULL;

	while (cnt--) {
		ins = strstr(orig, rep);
		len_front = ins - orig;
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep; // move to next "end of rep"
	}

	strcpy(tmp, orig);
	return result;
}

int restart_shorewall(const char *unit)
{
	DBusMessage *msg = NULL;
	DBusPendingCall *pending = NULL;
	DBusMessageIter args;

	const char *mode = "replace";

	int ret = 1;

	msg = dbus_message_new_method_call(
		"org.freedesktop.systemd1",
		"/org/freedesktop/systemd1",
		"org.freedesktop.systemd1.Manager",
		"ReloadUnit"
	);

	if (!msg)
	{
		ret = 0;
		goto cleanup;
	}

	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &unit))
	{
		ret = 0;
		goto cleanup;
	}

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &mode))
	{
		ret = 0;
		goto cleanup;
	}

	if (!dbus_connection_send_with_reply(dbus, msg, &pending, -1))
	{
		ret = 0;
		goto cleanup;
	}

	if (!pending)
	{
		ret = 0;
		goto cleanup;
	}

	dbus_connection_flush(dbus);
	dbus_message_unref(msg);
	msg = NULL;

	dbus_pending_call_block(pending);

cleanup:

	if (pending)
		dbus_pending_call_unref(pending);

	if (msg)
		dbus_message_unref(msg);

	return(ret);
}

/******************************************************************************/

char *shorewall(UDF_INIT *initid, UDF_ARGS *args,
			char *result, unsigned long *res_length, 
			char *null_value, char *error)
{
	char *host = args->args[0];
	char *macro = args->args[1];
	char *address = args->args[2];
	int  enabled = atoi(args->args[3]);
	char *format = args->args[4];

	char hostname[256],
		 filename[256],
		 filename6[256],
		 ipv6address[256],
		 needle[256];

	FILE *fp;
	struct addrinfo hint, *res;
	char *ipv4data = NULL, *ipv6data = NULL, *offset, *entry;

	size_t filesize = 0, filesize6 = 0, cnt;

	// Lookup hostname
	gethostname(hostname, sizeof(hostname) - 1);

	// Skip non-matching hosts	
	if (strcmp(hostname, host) != 0)
	{
		*null_value = 1;
		return NULL;
	}

	// Open file pointers
	snprintf(filename, sizeof(filename), "/etc/shorewall/macro.%s", macro);
	snprintf(filename6, sizeof(filename6), "/etc/shorewall6/macro.%s", macro);

	// Load IPv4 data
	if ((fp = fopen(filename, "a+")))
	{
		fseek(fp, 0L, SEEK_END);
		filesize = ftell(fp);
		rewind(fp);

		if (filesize && (ipv4data = malloc(filesize)))
		{
			fread(ipv4data, filesize, 1, fp);

			// Search and delete line
			snprintf(needle, sizeof(needle), "\t%s\t", address);

			while ((offset = strstr(ipv4data, needle)))
			{
				while (*offset && *offset != '\r' && *offset != '\n')
					offset--;

				offset++;

				cnt = 0;

				while (offset[cnt] && offset[cnt] != '\r' && offset[cnt] != '\n')
					cnt++;

				cnt++;

				while (offset[cnt] && (offset[cnt] == '\r' || offset[cnt] == '\n'))
					cnt++;

				memmove(offset, offset + cnt, filesize - (size_t)(offset - ipv4data));
				filesize -= cnt;
			}
		}

		fclose(fp);
	}

	// Load IPv6 data
	if ((fp = fopen(filename6, "a+")))
	{
		fseek(fp, 0L, SEEK_END);
		filesize6 = ftell(fp);
		rewind(fp);

		if (filesize6 && (ipv6data = malloc(filesize6)))
		{
			fread(ipv6data, filesize6, 1, fp);

			// Search and delete line
			snprintf(needle, sizeof(needle), "\t[%s]\t", address);

			while ((offset = strstr(ipv6data, needle)))
			{
				while (*offset && *offset != '\r' && *offset != '\n')
					offset--;

				offset++;

				cnt = 0;

				while (offset[cnt] && offset[cnt] != '\r' && offset[cnt] != '\n')
					cnt++;

				while (offset[cnt] && (offset[cnt] == '\r' || offset[cnt] == '\n'))
					cnt++;

				memmove(offset, offset + cnt, filesize6 - (size_t)(offset - ipv6data));
				filesize6 -= cnt;
			}
		}

		fclose(fp);
	}

	// Check IPv4/IPv6
	memset(&hint, '\0', sizeof(hint));

	hint.ai_family = PF_UNSPEC;
	hint.ai_flags = AI_NUMERICHOST;

	if (!(getaddrinfo(address, NULL, &hint, &res)))
	{
		switch (res->ai_family)
		{
			case AF_INET:
				if (enabled)
				{
					entry = str_replace(format, ":address", address);

					if (entry && (ipv4data = realloc(ipv4data, filesize + strlen(entry))))
					{
						memcpy(ipv4data + filesize, entry, strlen(entry));
						filesize += strlen(entry);
						free(entry);
					}
				}

				if ((fp = fopen(filename, "w")))
				{
					fwrite(ipv4data, filesize, 1, fp);
					fclose(fp);
				}

				break;

			case AF_INET6:
				if (enabled)
				{
					snprintf(ipv6address, sizeof(ipv6address), *address == '[' ? "%s" : "[%s]", address);

					entry = str_replace(format, ":address", ipv6address);

					if (entry && (ipv6data = realloc(ipv6data, filesize6 + strlen(entry))))
					{
						memcpy(ipv6data + filesize6, entry, strlen(entry));
						filesize6 += strlen(entry);
						free(entry);
					}
				}

				if ((fp = fopen(filename6, "w")))
				{
					fwrite(ipv6data, filesize6, 1, fp);
					fclose(fp);
				}
				break;

			default:break;
		}
	}

	freeaddrinfo(res);

	if (ipv4data) free(ipv4data);
	if (ipv6data) free(ipv6data);

	// Restart service
	if (!restart_shorewall("shorewall.service") || !restart_shorewall("shorewall6.service"))
	{
		*error = 1;
		*res_length = 27;
		strcpy(result, "Unable to reload shorewall");
		return result;
	}

	*res_length = 2;
	strcpy(result, "OK");
	return result;
} // shorewall

#endif /* HAVE_DLOPEN */
