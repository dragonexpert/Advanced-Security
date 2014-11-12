Advanced-Security
=================

For MyBB 1.8

Installation
============
1) Upload advanced_security.php to your inc/plugins directory.  
2) Upload modcp_sessions.php to your admin/modules/tools directory.  
3) Install and activate from the Admin CP.    
4) If you are not using MyBB 1.8.2 or later, you will need to edit your /inc/functions.php file. Look for the get_ip function.  Replace all content there with the get_ip function in mybb/mybb/feature branch.  

Configuring Admin Logins  

You will notice a field added to the Admin CP login form.  If you have specified $config['private_keys'][$userid]['hashvalue'] it will check if the contents of the file match the value in your inc/config.php file.  If they do not, the login fails and says the standard invalid username / password combination.  This is for improved security so they won't know the username and password may have been correct.  The other field that can be checked is the name of the file they upload.  It will hash the name of the file and see if it matches.  If it fails
the login will not work.  If $config['private_keys'][$userid]['filename'] is not set, it will not validate the name of the file.  I strongly encourage that you have your users name the file something weird.

You will have the users tell you the text that is in the file.  You will then get the sha1 value of that and put that for the hash key.  If you plan on implementing file names, you'll also need them to specify that for you.  
Example of config.php

$config['private_keys'][1]['hash'] = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
$config['private_keys'][1]['filename'] = "kadjakls.txt";


Support

Support is available based on the following guidelines:

1) Your forum must have the Powered By MyBB and link back to mybb.com.  
2) Your forum doesn't contain adult material, hacking, or illegal material.  
3) You post in Plugin Support on the official MyBB Community forums.  Do not PM / email me for support unless I specifically ask you to.  
4) For installation issues have an FTP account ready when you make your thread.  I will ask for that information to be sent to me via PM.  

The contents of this plugin may not be redistributed in whole or significant part to the public without written consent by Mark Janssen.

