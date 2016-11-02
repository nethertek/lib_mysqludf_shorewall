# lib_mysqludf_shorewall

A library to generate Shorewall macros and reload firewall rules via systemd (dbus)

**Copyright (C) 2016 NetherTek Engineering Innovations**

**web:** http://www.nethertek.net  
**email:** info@nethertek.net  

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

#### Compile with (adapt the include and lib path to your environment):

```
> gcc -Wall -O2 lib_mysqludf_shorewall.c \
	-I/usr/include/mysql \
	-I/usr/include/dbus-1.0
	-I/usr/lib64/dbus-1.0/include/  
	-shared -fPIC -o lib_mysqludf_shorewall.so
> strip ./lib_mysqludf_shorewall.so
```
   
#### Add the functions to MySQL with:

```
mysql> CREATE FUNCTION shorewall RETURNS STRING SONAME "lib_mysqludf_shorewall.so";
```
####Create the corresponding MySQL trigger (add another UPDATE trigger if required):

The function takes 5 parameters:  
* Hostname of machine to execute changes on  
(if the hostname does not match, processing stops)  
* Macro name for the shorewall rule  
* A valid IPv4 or IPv6 address  
* Enabled field, must be 1 to add rule, 0 removes rule  
* String to write to macro, **:address** will be replaced with IP address  

``` 
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
```

####Add a shorewall rule to shorewall and/or shorewall6:

```
MyMACRO(ACCEPT)	 net	 $FW
```

####Finally add a policy kit rule to /etc/polkit-1/rules.d/60-mysql.rules:

```
polkit.addRule(function(action, subject) {
	if (action.id == "org.freedesktop.systemd1.manage-units" &&
		subject.user == "mysql") {
		return polkit.Result.YES;
	} });
```

If everything is correct, it should now update and reload shorewall when  
changes are committed to the database. Don't forget to allow MySQL to write  
the macro file in the Shorewall directory. Tested on RHEL7 and compatible  
distributions.  
