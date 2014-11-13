<?php
if(!defined("IN_MYBB"))
{
    die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");
}

$superadmin = 0;

if(is_super_admin($mybb->user['uid']))
{
    $superadmin = 1;
}

$table = new TABLE;
$page->output_header("Mod CP Session Manager");
$page->add_breadcrumb_item("Mod CP Session Manager", "index.php?module=tools-modcp_sessions");

$sub_tabs['active_sessions'] = array(
"title" => "Active Sessions",
"link" => "index.php?module=tools-modcp_sessions",
"description" => "Active Sessions"
);

$sub_tabs['old_sessions'] = array(
"title" => "Old Sessions",
"link" => "index.php?module=tools-modcp_sessions&action=old_sessions",
"description" => "Old Sessions"
);

$sub_tabs['modcp_lockedout'] = array(
"title" => "Mod CP Locked Out",
"link" => "index.php?module=tools-modcp_sessions&action=modcp_lockout",
"description" => "Mod CP Locked Out Users"
);

$page->output_nav_tabs($sub_tabs);

if(!$mybb->input['action'])
{
    $mybb->input['action'] == "index";
}

if(!$mybb->input['action'] || $mybb->input['action'] == "index")
{
    advanced_security_list_modcp_sessions(1, $mybb->input['page']);
}

if($mybb->input['action'] == "old_sessions")
{
    advanced_security_list_modcp_sessions(0);
}

if($mybb->input['action'] == "destroy_session" && $mybb->input['sid'])
{
    advanced_security_destroy_session($mybb->input['sid']);
}

if($mybb->input['action'] == "deny_modcp" && $mybb->input['sid'])
{
    advanced_security_deny_modcp($mybb->input['sid']);
}

if($mybb->input['action'] == "modcp_lockout")
{
    advanced_security_modcp_lockout();
}

if($mybb->input['action'] == "unlock_modcp" && $mybb->input['sid'])
{
    if($superadmin)
    {
        $userid = intval($mybb->input['sid']);
        $db->query("UPDATE " . TABLE_PREFIX . "users SET modcp_lockout=0 WHERE uid=$userid");
        log_admin_action("Moderator CP Access");
        flash_message("The user has gotten their Mod CP access back.", "success");
    }
    else
    {
        flash_message("Youare not authorized to perform this action.", "error");
        admin_redirect("index.php?module=tools-modcp_sessions");
    }
}

function advanced_security_modcp_lockout()
{
    global $mybb, $db, $superadmin, $table;
    $query = $db->simple_select("users", "uid, username, lastactive, lastip", "modcp_lockout=1 ORDER BY username ASC LIMIT 50");
    // If they have more than 50 locked out moderators, they have bigger issues.
    $table->construct_header("Username");
    $table->construct_header("Last IP");
    $table->construct_header("Last Active");
    if($superadmin)
    {
        $table->construct_header("Manage");
    }
    $table->construct_row();
    while($lockeduser = $db->fetch_array($query))
    {
        $table->construct_cell($lockeduser['username']);
        $table->construct_cell($lockeduser['lastip']);
        $table->construct_cell(my_date("relative", $lockeduser['lastactive']));
        if($superadmin)
        {
            $content = "<a href=\"index.php?module=tools-modcp_sessions&action=unlock_modcp&sid=" . $lockeduser['uid'] . "\">Remove Block</a>";
            $table->construct_cell($content);
        }
        $table->construct_row();
    }
    $table->output("Users Blocked From Mod CP");
}

function advanced_security_deny_modcp($sid)
{
    global $mybb, $db, $superadmin;
    if(!$superadmin)
    {
        flash_message("You are not authorized to do this action.", "error");
        admin_redirect("index.php?module=tools-modcp_sessions");
        die();
    }
    $sid = $db->escape_string($sid);
    // First we want to query the session and stop the attempt if the session belongs to a super admin.
    $queryfirst = $db->simple_select("modcp_sessions", "*", "loginkey=$sid");
    $modcp_session = $db->fetch_array($queryfirst);
    if(is_super_admin($modcp_session['uid']))
    {
        flash_message("You are not authorized to do this action.", "error");
        admin_redirect("index.php?module=tools-modcp_sessions");
    }
    else
    {
        $db->query("UPDATE " . TABLE_PREFIX . "users SET modcp_lockout=1 WHERE uid=" . $modcp_session['uid']);
        log_admin_action("Mod CP Sessions");
        flash_message("You have denied access to the Mod CP for user " . $modcp_session['uid'], "success");
        admin_redirect("index.php?module=tools-modcp_sessions");
    }
}

function advanced_security_destroy_session($sid)
{
    global $mybb, $db, $superadmin;
    if(!$superadmin)
    {
        flash_message("You are not authorized to do this action.", "error");
        admin_redirect("index.php?module=tools-modcp_sessions");
        die();
    }
    $sid = $db->escape_string($sid);
    // First we want to query the session and stop the attempt if the session belongs to a super admin.
    $queryfirst = $db->simple_select("modcp_sessions", "*", "loginkey=$sid");
    $modcp_session = $db->fetch_array($queryfirst);
    if(is_super_admin($modcp_session['uid']))
    {
        flash_message("You are not authorized to do this action.", "error");
        admin_redirect("index.php?module=tools-modcp_sessions");
    }
    else
    {
        $db->query("UPDATE " . TABLE_PREFIX . "modcp_sessions SET loginkey='' WHERE loginkey='$sid'");
        log_admin_action("Mod CP Sessions");
        flash_message("The session has been destroyed.", "success");
        admin_redirect("index.php?module=tools-modcp_sessions");
    }
}

function advanced_security_list_modcp_sessions($active=1, $pagenumber=1)
{
    global $mybb, $db, $table, $superadmin;
    $cutoff = TIME_NOW - 3600;
    $url = "index.php?module=tools-modcp_sessions";
    if(!$active)
    {
        $cutoff = 0;
        $max = TIME_NOW - 3600;
        $activepart = " AND m.lastmodaction <= $max ";
        $url = "index.php?module=tools-modcp_sessions&action=old_sessions";
    }
    // Count the number of rows
    $countquery = $db->simple_select("modcp_sessions m", "COUNT(m.sid) as total", "m.lastmodaction >= $cutoff $activepart AND m.loginkey != ''");
    $records = $db->fetch_field($countquery, "total");
    $pagecount = ceil($records / 50);
    $admin_pagination = draw_admin_pagination(intval($pagenumber), 50, $records, $url);
    echo $admin_pagination;
    if($pagenumber <= 1)
    {
     $query = $db->query("SELECT m.*, u.username, u.modcp_lockout
     FROM " . TABLE_PREFIX . "modcp_sessions m
     LEFT JOIN " . TABLE_PREFIX . "users u ON(m.uid=u.uid)
     WHERE m.lastmodaction >= $cutoff $activepart AND m.loginkey != ''
     ORDER BY m.lastmodaction DESC
     LIMIT 50");
    }
    else
    {
        $start = 50 * $pagenumber - 50;
        $query = $db->query("SELECT m.*, u.username, u.modcp_lockout
     FROM " . TABLE_PREFIX . "modcp_sessions m
     LEFT JOIN " . TABLE_PREFIX . "users u ON(m.uid=u.uid)
     WHERE m.lastmodaction >= $cutoff $activepart AND m.loginkey != ''
     ORDER BY m.lastmodaction DESC
     LIMIT $start, 50");
    }
    $table->construct_header("Username");
    $table->construct_header("IP Address");
    $table->construct_header("Last Active");
    if($superadmin)
    {
        $table->construct_header("Manage");
    }
    $table->construct_row();
    while($modcp_session = $db->fetch_array($query))
    {
        $table->construct_cell($modcp_session['username']);
        $table->construct_cell($modcp_session['ipaddress']);
        $table->construct_cell(my_date($mybb->settings['timeformat'], $modcp_session['lastmodaction']));
        if($superadmin)
        {
            if($active)
            {
                $content = "<a href=\"index.php?module=tools-modcp_sessions&action=destroy_session&sid=" . $modcp_session['loginkey'] . "\">Destroy Session</a><br />";
            }
            $content .= "<a href=\"index.php?module=tools-modcp_sessions&action=deny_modcp&sid=" .$modcp_session['loginkey'] . "\">Block Mod CP Access</a>";
            if(is_super_admin($modcp_session['uid']))
            {
                $content = "You are unable to manage this user's session";
            }
            $table->construct_cell($content);
        }
        $table->construct_row();
    }
    $table->output("Mod CP Sessions");
    echo $admin_pagination;
}

$page->output_footer();
?>
