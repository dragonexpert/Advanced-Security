Advanced-Security
=================

For MyBB 1.8

Installation
============
1) Upload advanced_security.php to your inc/plugins directory.  
2) Upload modcp_sessions.php to your admin/modules/tools directory.  
3) Install and activate from the Admin CP.    
  

Configuring Admin Logins  
========================

You will notice a field added to the Admin CP login form.  If you have specified $config['private_keys'][$userid]['hashvalue'] it will check if the contents of the file match the value in your inc/config.php file.  If they do not, the login fails and says the standard invalid username / password combination.  This is for improved security so they won't know the username and password may have been correct.  The other field that can be checked is the name of the file they upload.  It will hash the name of the file and see if it matches.  If it fails
the login will not work.  If $config['private_keys'][$userid]['filename'] is not set, it will not validate the name of the file.  I strongly encourage that you have your users name the file something weird.

You will have the users tell you the text that is in the file.  You will then get the sha1 value of that and put that for the hash key.  If you plan on implementing file names, you'll also need them to specify that for you.  
Example of config.php

$config['private_keys'][1]['hash'] = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
$config['private_keys'][1]['filename'] = "kadjakls.txt";

Admin IP Manager
================

IP Addresses are logged as of version 2.0.  If the user who tries to log in does not have an IP in the whitelist, they will
be unable to log in.  At this point, it will then verify if the username entered can in fact access the Admin CP.  It also makes sure the IP Address is not specifically blocked from accessing the Admin CP.  If it passes those conditions it will send an email to the account that has a special code in the link.  If the user clicks that link, they will be able to add their IP to the whitelist.  It should be noted that links sent in the email expire in 2 hours for security reasons.  This can be adjusted by manually editing the advanced_security_add_ip function in /inc/plugins/advanced_security.php.

Once this plugin is installed, it attempts to add the last known IP of each person that can access the Admin CP.  This makes it less worry for you being forced to add their IP.  There is also a module for adding / deleting / blocking IPs access of the Admin CP.  Adding and blocking can be done either by IP or username to get the correct values.  Deleting the access is as easy as clicking a link that says Remove IP.

The system also can manage itself in the Admin CP.  If the same IP has failed the Admin CP Login 3 times within 24 hours, the IP Address is immediately added to a blacklist, making it impossible for the IP to be added without manipulating the database.  It also sends an email to the admin email specified under Board Settings. 

Mod CP Session Manager
======================

This tools lets you view both active and inactive moderator sessions. It will say the last active time of the session, the username, and the IP Address associated with the session.  Active sessions can also be destroyed by a super admin.  A super admin is also able to block Mod CP access for a user.  The system will also stop two IPs from being logged in at the same time as the same user.

Support
=======
Support is available based on the following guidelines:

1) Your forum must have the Powered By MyBB and link back to mybb.com.  
2) Your forum doesn't contain adult material, hacking, or illegal material.  
3) You post in Plugin Support on the official MyBB Community forums.  Do not PM / email me for support unless I specifically ask you to.  
4) For installation issues have an FTP account ready when you make your thread.  I will ask for that information to be sent to me via PM.  

The contents of this plugin may not be redistributed in whole or significant part to the public without written consent by Mark Janssen.

