<?php

if(!defined("IN_MYBB"))
{
    die("Direct access not allowed.");
}

// Define the hooks
// Log in for Mod CP
$plugins->add_hook("modcp_start", "advanced_security_modcp");
// Log out when logging out
$plugins->add_hook("member_logout_end", "advanced_security_logout");
// Admin Menu
$plugins->add_hook("admin_tools_menu_logs", "advanced_security_tool_menu");
// Admin Action Handler
$plugins->add_hook("admin_tools_action_handler", "advanced_security_tool_action_handler");
// Admin Log In
$plugins->add_hook("admin_page_show_login_end", "advanced_security_admin_login");
$plugins->add_hook("admin_load", "advanced_security_do_login");

// Return the info
function advanced_security_info()
{
        return array(
        "name"	=> "Advanced Forum Security",
		"description"		=> "A plug-in that improves security by making the MOD CP require an additional login.  Also include a session manager.",
		"website"		=> "",
		"author"		=> "Mark Janssen",
		"authorsite"		=> "",
		"version"		=> "2.0",
		"guid" 			=> "af4b485d999eda33cd04a6381b698ac6",
        "codename" => "advanced_security",
		"compatibility"	=> "18*"
    );
}

function advanced_security_install()
{
    global $mybb, $db;
    $characterset = $db->build_create_table_collation();
    if(!$db->table_exists("modcp_sessions"))
    {
        $db->query("CREATE TABLE " . TABLE_PREFIX . "modcp_sessions (
        sid INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        uid INT NOT NULL DEFAULT 1,
        ipaddress VARCHAR(15),
        dateline BIGINT,
        lastmodaction BIGINT,
        loginkey VARCHAR(50)
        ) ENGINE = Innodb $characterset");
    }

    if(!$db->table_exists("admin_ips"))
    {
        $db->write_query("CREATE TABLE " . TABLE_PREFIX . "admin_ips (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        uid INT NOT NULL DEFAULT 1,
        username VARCHAR(50),
        ipaddress VARCHAR(15),
        allow_disallow INT NOT NULL DEFAULT 1
        ) ENGINE = Innodb $characterset");
    }

    if(!$db->field_exists("modcp_lockout", "users"))
    {
         $db->add_column("users", "modcp_lockout", "TINYINT(1) DEFAULT 0");
    }
}

function advanced_security_is_installed()
{
    global $db;
    if($db->table_exists("modcp_sessions") && $db->table_exists("admin_ips"))
    {
        return true;
    }
    return false;
}

function advanced_security_activate()
{
    global $db, $mybb, $cache;
    // Assume the last ips for admins are allowed.
    // Get usergroups with ACP access
	$usergroups = array();
	$query = $db->simple_select("usergroups", "*", "cancp = 1");
	while($usergroup = $db->fetch_array($query))
	{
		$usergroups[$usergroup['gid']] = $usergroup;
	}
	// Get users whose primary or secondary usergroup has ACP access
	$comma = $primary_group_list = $secondary_group_list = '';
	foreach($usergroups as $gid => $group_info)
	{
		$primary_group_list .= $comma.$gid;
		switch($db->type)
		{
			case "pgsql":
			case "sqlite":
				$secondary_group_list .= " OR ','|| u.additionalgroups||',' LIKE '%,{$gid},%'";
				break;
			default:
				$secondary_group_list .= " OR CONCAT(',', u.additionalgroups,',') LIKE '%,{$gid},%'";
		}
		$comma = ',';
	}
	$group_list = implode(',', array_keys($usergroups));
	$secondary_groups = ','.$group_list.',';
    $query = $db->query("
		SELECT u.uid, u.username, u.lastactive, u.usergroup, u.additionalgroups, u.lastip, a.permissions
		FROM ".TABLE_PREFIX."users u
		LEFT JOIN ".TABLE_PREFIX."adminoptions a ON (a.uid=u.uid)
		WHERE u.usergroup IN ({$primary_group_list}) {$secondary_group_list}
		ORDER BY u.username ASC
	");
	while($admin = $db->fetch_array($query))
	{
		$allowedip[] = array(
        "uid" => $admin['uid'],
        "username" => $admin['username'],
        "ipaddress" => $admin['lastip'],
        "allow_disallow" => 1
        );
    }
    $db->insert_query_multiple("admin_ips", $allowedip);
    // Now cache the ips
    $query = $db->simple_select("admin_ips", "*", "allow_disallow = 1", array("order_by"=> "uid", "order_dir" => "ASC"));
    $data = "";
    while($ip = $db->fetch_array($query))
    {
        $data[$ip['uid']][] = $ip;
    }
    $cache->update("admin_ips", $data);
}

function advanced_security_deactivate()
{
    // Silence
}

function advanced_security_uninstall()
{
    global $db;
    $db->drop_table("modcp_sessions", true, true);
    $db->drop_column("users", "modcp_lockout");
}

function advanced_security_modcp()
{
   global $mybb, $db;
   require_once MYBB_ROOT . "inc/functions_user.php";
   // First check if they are locked out of the Mod CP
   if($mybb->user['modcp_lockout'] && is_super_admin($mybb->user['uid']))
   {
       error_no_permission();
   }
   // Now check for duplicate sessions.  Invalidate all session that are duplicates.
   if(advanced_security_multiple_session_detector())
   {
       advanced_security_modcp_session_destroyer($mybb->user['uid']);
       $url = "modcp.php";
       $message = "Multiple sessions were detected.  You are now being logged out.";
       redirect($url, $message);
   }
    // Now check for the cookie
    if($mybb->cookies['modcplogin'])
    {
        // Validate their session is valid on the server
      $query = $db->simple_select("modcp_sessions", "sid, loginkey", "sid=" . $mybb->cookies['modcplogin']);
      $modcp_session = $db->fetch_array($query);
      if($modcp_session['loginkey']) // This can give an option for admins to kick out a moderator
      {
          my_setcookie("modcplogin", $mybb->cookies['modcplogin'], 3600);
          advanced_security_update_modcp_session($modcp_session['sid']);
      }
      else
      {
          if($mybb->request_method == "post")
          {
              advanced_security_insert_modcp_session();
              my_setcookie("modcplogin", $db->insert_id(), 3600);
              $url = "modcp.php";
              if($mybb->input['action'])
              {
                  $url .= "?action=" . $mybb->input['action'];
              }
              $message = "Thank you for logging into the Mod CP";
              redirect($url, $message);
          }
          else
          {
            advanced_security_generate_login_box();
          }
      } // End no loginkey
      if($mybb->input['action']=="modcp_logout")
      {
          advanced_security_logout_modcp();
      }
    } // End modcplogin cookie set
    else
    {
       // Don't show the form if posting and correct
       if($mybb->request_method == "post")
       {
            verify_post_check($mybb->input['my_post_key']);
            if(!validate_password_from_username($mybb->input['modcpusername'], $mybb->input['modcppassword']))
            {
                login_attempt_check(true);
                advanced_security_generate_login_box();
            }
            advanced_security_insert_modcp_session();
            // No errors so we can set a cookie
            my_setcookie("modcplogin", $db->insert_id(), 3600);
            $url = "modcp.php";
            if($mybb->input['action'])
            {
                $url .= "?action=" . $mybb->input['action'];
            }
            $message = "Thank you for logging into the Mod CP";
            redirect($url, $message);
       }
       else
       {
           advanced_security_generate_login_box();
       }
    }
}

function advanced_security_generate_login_box()
{
    global $mybb, $header, $headerinclude, $footer;
    $content = "<form action=\"modcp.php\" method=\"post\">
    <input type=\"hidden\" name=\"my_post_key\" value=\"" . $mybb->post_code . "\">";
    if($mybb->input['action'])
    {
        $content .= "<input type=\"hidden\" name=\"action\" value=\"" . $mybb->input['action'] . "\" />";
    }
    $content .= "Username: <input type=\"text\" name=\"modcpusername\" value=\"" . $mybb->user['username'] . "\" required=\"required\"><br />
    Password: <input type=\"password\" name=\"modcppassword\" required=\"required\"><br />
    <input type=\"submit\" value=\"Log In\" />";
    $content = $headerinclude . $header . $content . $footer;
    output_page($content);
    die();
}

function advanced_security_insert_modcp_session()
{
    global $mybb, $db;
    $loginkey = generate_loginkey();
    $modcpinfo = array(
    "uid" => $mybb->user['uid'],
    "ipaddress" => $_SERVER['REMOTE_ADDR'],
    "dateline" => TIME_NOW,
    "lastmodaction" => TIME_NOW,
    "loginkey" => $loginkey
    );
    $db->insert_query("modcp_sessions", $modcpinfo);
}

function advanced_security_update_modcp_session($sid)
{
    global $mybb, $db;
     $modcpinfo = array(
    "uid" => $mybb->user['uid'],
    "ipaddress" => $_SERVER['REMOTE_ADDR'],
    "dateline" => TIME_NOW,
    "lastmodaction" => TIME_NOW
    );
    $db->update_query("modcp_sessions", $modcpinfo, "sid=$sid");
}

function advanced_security_logout()
{
    global $mybb, $db;
    $sid = intval($mybb->cookies['sid']);
    $db->query("UPDATE " . TABLE_PREFIX . "modcp_sessions SET loginkey='' WHERE sid=$sid");
    my_unsetcookie("modcplogin");
}

function advanced_security_logout_modcp()
{
    global $mybb;
    my_unsetcookie("modcplogin");
    $url = "modcp.php";
    $message = "You have been logged out of the Mod CP";
    redirect($url, $message);
}

/* This checks for multiple sessions. */
function advanced_security_multiple_session_detector()
{
    global $mybb, $db;
    $cutoff = TIME_NOW - 3600;
    $query = $db->simple_select("modcp_sessions", " DISTINCT ipaddress, COUNT(*) as session_total", "uid=". $mybb->user['uid'] . " AND lastmodaction >= $cutoff AND loginkey != ''");
    $sessioncount = $db->fetch_field($query, "session_total");
    if($sessioncount <= 1)
    {
        return false;
    }
    return true;
}

/* This kills any sessions where a duplicate session is also active */
function advanced_security_modcp_session_destroyer($userid)
{
    global $mybb, $db;
    $userid = intval($userid);
    $cutoff = TIME_NOW - 3600;
    $db->query("UPDATE " . TABLE_PREFIX . "modcp_sessions SET loginkey='' WHERE uid=$userid AND lastmodaction >=$cutoff");
}

function advanced_security_tool_menu(&$sub_menu)
{
    global $mybb;
    $key = count($sub_menu) * 10 + 10;
    $sub_menu[$key] = array(
    "id" => "modcp_sessions",
    "title" => "Mod CP Session Manager",
    "link" => "index.php?module=tools-modcp_sessions"
    );
    $key += 10;
    $sub_menu[$key] = array(
    "id" => "admin_ips",
    "title" => "Admin IP Manager",
    "link" => "index.php?module=tools-admin_ips"
    );
    $key += 10;
    $sub_menu[$key] = array(
    "id" => "admincp_sessions",
    "title" => "Admin CP Session Manager",
    "link" => "index.php?module=tools-admincp_sessions"
    );
}

function advanced_security_tool_action_handler(&$actions)
{
    $actions['modcp_sessions'] = array(
    "active" => "modcp_sessions",
    "file" => "modcp_sessions.php"
    );
    $actions['admin_ips'] = array(
    "active" => "admin_ips",
    "file" => "admin_ips.php"
    );
    $actions['admincp_sessions'] = array(
    "active" => "admincp_sessions",
    "file" => "admincp_sessions.php"
    );
}

function advanced_security_admin_login(&$args)
{
    global $mybb, $config, $secret_pin, $login_label_width, $login_lang_string, $query_string, $lang, $login_container_width, $cp_style, $copy_year, $lang_username;
    $login_lang_string = $lang->enter_username_and_password;

		switch($mybb->settings['username_method'])
		{
			case 0: // Username only
				$login_lang_string = $lang->sprintf($login_lang_string, $lang->login_username);
				break;
			case 1: // Email only
				$login_lang_string = $lang->sprintf($login_lang_string, $lang->login_email);
				break;
			case 2: // Username and email
			default:
				$login_lang_string = $lang->sprintf($login_lang_string, $lang->login_username_and_password);
				break;
		}
        $lang_username = $lang->username;
    $login_page = <<<EOF
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head profile="http://gmpg.org/xfn/1">
<title>{$lang->mybb_admin_login}</title>
<meta name="author" content="MyBB Group" />
<meta name="copyright" content="Copyright {$copy_year} MyBB Group." />
<link rel="stylesheet" href="./styles/{$cp_style}/login.css" type="text/css" />
<script type="text/javascript" src="../jscripts/jquery.js"></script>
<script type="text/javascript" src="../jscripts/general.js"></script>
<script type="text/javascript" src="./jscripts/admincp.js"></script>
<script type="text/javascript">
//<![CDATA[
	loading_text = '{$lang->loading_text}';
//]]>
</script>
</head>
<body>
<div id="container"{$login_container_width}>
	<div id="header">
		<div id="logo">
			<h1><a href="../" title="{$lang->return_to_forum}"><span class="invisible">{$lang->mybb_acp}</span></a></h1>

		</div>
	</div>
	<div id="content">
		<h2>{$lang->please_login}</h2>
EOF;
        if(isset($config['secret_pin']) && $config['secret_pin'] != '')
		{
			$secret_pin = "<div class=\"label\"{$login_label_width}><label for=\"pin\">{$lang->secret_pin}</label></div>
            <div class=\"field\"><input type=\"password\" name=\"pin\" id=\"pin\" class=\"text_input\" /></div>";
		}
        if(isset($config['private_keys']))
        {
          $file_upload_field = "<div class=\"label\"{$login_label_width}><label for=\"privatekey\">Private Key</label></div>
         <div class=\"field\"><input type=\"file\" name=\"privatekey\" id=\"privatekey\" /></div>";
      
         }

        $login_page .= <<<EOF
		<p>{$login_lang_string}</p>
		<form method="post" action="{$_SERVER['PHP_SELF']}{$query_string}" enctype="multipart/form-data">
		<div class="form_container">

			<div class="label"{$login_label_width}><label for="username">{$lang_username}</label></div>

			<div class="field"><input type="text" name="username" id="username" class="text_input initial_focus" /></div>

			<div class="label"{$login_label_width}><label for="password">{$lang->password}</label></div>
			<div class="field"><input type="password" name="password" id="password" class="text_input" /></div>
            {$secret_pin}
            {$file_upload_field}
		</div>
		<p class="submit">
			<span class="forgot_password">
				<a href="../member.php?action=lostpw">{$lang->lost_password}</a>
			</span>

			<input type="submit" value="{$lang->login}" />
			<input type="hidden" name="do" value="login" />
		</p>
		</form>
	</div>
</div>
</body>
</html>
EOF;
$args['login_page'] = $login_page;
}

function advanced_security_do_login()
{
    global $config, $mybb, $page, $db, $lang;
    if(!defined("IN_ADMINCP"))
    {
        return;
    }
     // Now perform more validation
    $userid = $mybb->user['uid'];
    $valid = advanced_security_check_ip($userid);
    if(!$valid)
    {
        $mybb->user['uid'] = "";
        // Delete the admin session
        $db->delete_query("adminsessions", "sid='".$db->escape_string($mybb->cookies['adminsid'])."'");
		my_unsetcookie('adminsid');
		$logged_out = true;
    }
    if($mybb->input['do'] != "login")
    {
        return;
    }
    if(!array_key_exists("private_keys", $config) && $valid)
    {
        return;
    }
    if(array_key_exists($userid, $config['private_keys']))
    {
        if(!$_FILES['privatekey']['tmp_name'])
        {
            $mybb->user['uid']= "";
            $filecontents = "";
        }
        else
        {
            $filelocation = $_FILES['privatekey']['tmp_name'];
            $filecontents = sha1(file_get_contents($filelocation));
        }
        if(array_key_exists("hashvalue", $config['private_keys'][$userid]))
        {
            // Now we have our values, time to test them
            if($filecontents != $config['private_keys'][$userid]['hashvalue'])
            {
                $mybb->user['uid'] = "";
            }
            // Check if they actually are forcing a file name.  If so also verify this.
            if(array_key_exists("filename", $config['private_keys'][$userid]))
            {
                $filename = $_FILES['privatekey']['name'];
                if($filename != $config['private_keys'][$userid]['filename'])
                {
                    $mybb->user['uid'] = "";
                }
                else
                {
                    return;
                }
            }
            if(!$mybb->user['uid'])
            {
                // Delete the admin session
                $db->delete_query("adminsessions", "sid='".$db->escape_string($mybb->cookies['adminsid'])."'");
		        my_unsetcookie('adminsid');
		        $logged_out = true;
                $login_lang_string = $lang->error_invalid_username_password;

		        switch($mybb->settings['username_method'])
		        {
			        case 0: // Username only
				        $login_lang_string = $lang->sprintf($login_lang_string, $lang->login_username);
				           break;
			        case 1: // Email only
				         $login_lang_string = $lang->sprintf($login_lang_string, $lang->login_email);
				            break;
			        case 2: // Username and email
			        default:
				    $login_lang_string = $lang->sprintf($login_lang_string, $lang->login_username_and_password);
				    break;
		        }
                $page->show_login($login_lang_string, "error");
                die;
            }
        }
    }
}

function advanced_security_check_ip($userid)
{
    global $mybb, $db, $cache;
    $valid = 0;
    $my_ip = get_ip();
    $ipaddresses = $cache->read("admin_ips");
    if(array_key_exists($userid, $ipaddresses))
    {
        foreach($ipaddresses as $ipaddress)
        {
            foreach($ipaddress as $ip)
            {
                if($ip['ipaddress'] == $my_ip)
                {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

function advanced_security_update_admin_ip_cache()
{
    global $db, $cache;
    $query = $db->simple_select("admin_ips", "*", "allow_disallow = 1", array("order_by"=> "uid", "order_dir" => "ASC"));
    $data = "";
    while($ip = $db->fetch_array($query))
    {
        $data[$ip['uid']][] = $ip;
    }
    $cache->update("admin_ips", $data);
}

function advanced_security_verify_ip($ip)
{
    if(!strpos(".", $ip))
    {
        return FALSE;
    }
    $exip = explode(".", $ip);
    // Not forcing all four octets in case a future release I allow three octet inputs
    foreach($exip as $ipaddress)
    {
        $ipaddress = (int) $ipaddress;
        if(!$ipaddress || $ipaddress < 1 || $ipaddress > 255)
        {
            return FALSE;
        }
    }
    return TRUE;
}

function advanced_security_add_ip($ip)
{
    global $mybb, $db;
    if(!advanced_security_verify_ip($ip))
    {
        error("Invalid IP.");
    }
    // First get the blocked IPs so it can't be added if it exists in them.
    $query = $db->simple_select("admin_ips", "*", "allow_disallow=0");
    while($blockedip = $db->fetch_array($query))
    {
        $bannedips[] = $blockedip['ipaddress'];
    }
    if(in_array($ip, $bannedips))
    {
        error("This IP is not allowed to access the ACP.");
    }
    // All checks are good. Add the IP to the whitelist.
    $new_ip = array(
    "uid" => $mybb->user['uid'],
    "username" => $mybb->user['username'],
    "ipaddress" => $db->escape_string($ip),
    "allow_disallow" => 1
    );
    $db->insert_query("admin_ips", $new_ip);
    advanced_security_update_admin_ip_cache();
}

?>
