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
$page->output_header("Admin CP Session Manager");
$page->add_breadcrumb_item("Admin CP Session Manager", "index.php?module=tools-admincp_sessions");

$sub_tabs['active_sessions'] = array(
"title" => "Active Sessions",
"link" => "index.php?module=tools-admincp_sessions",
"description" => "Active Sessions"
);

$sub_tabs['old_sessions'] = array(
"title" => "Old Sessions",
"link" => "index.php?module=tools-admincp_sessions&action=old_sessions",
"description" => "Old Sessions"
);

$page->output_nav_tabs($sub_tabs);

if(!$mybb->input['action'])
{
    $mybb->input['action'] == "index";
}

if(!$mybb->input['action'] || $mybb->input['action'] == "index")
{
    advanced_security_list_admincp_sessions(1, $mybb->input['page']);
}

if($mybb->input['action'] == "old_sessions")
{
    advanced_security_list_admincp_sessions(0);
}

if($mybb->input['action'] == "destroy_session" && $mybb->input['sid'])
{
    advanced_security_destroy_admin_session($mybb->input['sid']);
}

function advanced_security_list_admincp_sessions($active=1, $pagenumber=1)
{
    global $mybb, $db, $table, $superadmin;
    $cutoff = TIME_NOW - 3600;
    $url = "index.php?module=tools-admincp_sessions";
    if(!$active)
    {
        $cutoff = 0;
        $max = TIME_NOW - 3600;
        $activepart = " AND a.lastactive <= $max ";
        $url = "index.php?module=tools-admincp_sessions&action=old_sessions";
    }
    // Count the number of rows
    $countquery = $db->simple_select("adminsessions a", "COUNT(a.sid) as total", "a.lastactive >= $cutoff AND a.loginkey != ''");
    $records = $db->fetch_field($countquery, "total");
    $pagecount = ceil($records / 50);
    $admin_pagination = draw_admin_pagination(intval($pagenumber), 50, $records, $url);
    echo $admin_pagination;
    if($pagenumber <= 1)
    {
        $query = $db->query("SELECT a.*, u.username
            FROM " . TABLE_PREFIX . "adminsessions a
            LEFT JOIN " . TABLE_PREFIX . "users u ON(a.uid=u.uid)
            WHERE a.lastactive >= $cutoff AND a.loginkey != ''
            ORDER BY a.lastactive DESC
            LIMIT 50");
    }
    else
    {
        $start = 50 * $pagenumber - 50;
        $query = $db->query("SELECT a.*, u.username
            FROM " . TABLE_PREFIX . "adminsessions a
            LEFT JOIN " . TABLE_PREFIX . "users u ON(a.uid=u.uid)
            WHERE a.lastactive >= $cutoff AND a.loginkey != ''
            ORDER BY a.lastactive DESC
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
    while($admincp_session = $db->fetch_array($query))
    {
        $admincp_session['ip'] = my_inet_ntop($db->unescape_binary($admincp_session['ip']));
        $table->construct_cell($admincp_session['username']);
        $table->construct_cell($admincp_session['ip']);
        $table->construct_cell(my_date("relative", $admincp_session['lastactive']));
        if($superadmin)
        {
            if($active)
            {
                $content = "<a href=\"index.php?module=tools-admincp_sessions&action=destroy_session&sid=" . $admincp_session['loginkey'] . "\">Destroy Session</a><br />";
            }
            if(is_super_admin($admincp_session['uid']))
            {
                $content = "You are unable to manage this user's session";
            }
            $table->construct_cell($content);
        }
        $table->construct_row();
    }
    $table->output("Admin CP Sessions");
    echo $admin_pagination;
}

function advanced_security_destroy_admin_session($sid)
{
    global $mybb, $db, $superadmin;
    $sid = $db->escape_string($sid);
    // First we want to query the session and stop the attempt if the session belongs to a super admin.
    $queryfirst = $db->simple_select("admincp_sessions", "*", "loginkey=$sid");
    $admincp_session = $db->fetch_array($queryfirst);
    if(is_super_admin($admincp_session['uid']))
    {
        flash_message("You are not authorized to do this action.", "error");
        admin_redirect("index.php?module=tools-admincp_sessions");
    }
    else
    {
        $db->query("UPDATE " . TABLE_PREFIX . "adminsessions SET loginkey='' WHERE loginkey='$sid'");
        log_admin_action("Admin CP Sessions");
        flash_message("The session has been destroyed.", "success");
        admin_redirect("index.php?module=tools-admincp_sessions");
    }
}

$page->output_footer();
?>
