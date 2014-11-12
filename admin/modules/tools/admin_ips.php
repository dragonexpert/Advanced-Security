<?php
    
$page->output_header("Admin IP Manager");
$page->add_breadcrumb_item("Admin IP Manager", "index.php?module=tools-admin_ips");

if($mybb->input['action'] == "deleteip")
{
    verify_post_check($mybb->input['my_post_key']);
    $id = (int) $mybb->input['id'];
    $db->delete_query("admin_ips", "id=$id");
    advanced_security_update_admin_ip_cache();
    flash_message("The IP has been removed.", "success");
    admin_redirect("index.php?module=tools-admin_ips");
}

if($mybb->input['action'] == "blockip")
{
    verify_post_check($mybb->input['my_post_key']);
    $id = (int) $mybb->input['id'];
    $db->write_query("UPDATE " . TABLE_PREFIX . "admin_ips SET allow_disallow=0 WHERE id=$id");
    advanced_security_update_admin_ip_cache();
    flash_message("The IP has been blocked.", "success");
    admin_redirect("index.php?module=tools-admin_ips");
}

if($mybb->input['action'] == "addip")
{
    verify_post_check($mybb->input['my_post_key']);
    advanced_security_verify_ip($mybb->input['ipaddress']);
    $escaped_ip = my_inet_pton($db->escape_binary($mybb->input['ipaddress']));
    // Check the user table to attempt to get a username and uid
    $query = $db->simple_select("users", "uid, username", "lastip='" . $escaped_ip . "'");
    $ip_data = $db->fetch_array($query);
    if(!$db->num_rows($query))
    {
        $ip_data['uid'] = $mybb->user['uid'];
        $ip_data['username'] = $mybb->user['username'];
        $special = " No user with a last ip of " . $mybb->input['ipaddress'] . " were found, assuming current user.";
    }
    $new_ip = array(
    "ipaddress" => $db->escape_string($mybb->input['ipaddress']),
    "uid" => (int) $ip_data['uid'],
    "username" => $db->escape_string($ip_data['username']),
    "allow_disallow" => (int) $mybb->input['allow_disallow']
    );
    $db->insert_query("admin_ips", $new_ip);
    flash_message("Added the IP successfully. $special", "success");
    admin_redirect("index.php?module=tools-admin_ips");
}

if($mybb->input['action'] == "addusername")
{
    verify_post_check($mybb->input['my_post_key']);
    $query = $db->simple_select("users", "uid, username, lastip", "username='" . $db->escape_string($mybb->input['ipusername']) . "'");
    $ip_data = $db->fetch_array($query);
    if(!$db->num_rows($query))
    {
        flash_message("No users were found.", "error");
        admin_redirect("index.php?module=tools-admin_ips");
    }
    $insert_ip = array(
    "uid" => $ip_data['uid'],
    "username" => $ip_data['username'],
    "ipaddress" => my_inet_ntop($db->unescape_binary($ip_data['lastip'])),
    "allow_disallow" => (int) $mybb->input['allow_disallow']
    );
    $db->insert_query("admin_ips", $insert_ip);
    flash_message("Added the IP successfully.", "success");
    admin_redirect("index.php?module=tools-admin_ips");
}

$page->add_breadcrumb_item("Admin IP Manager", "index.php?module=tools-admin_ips");

$query = $db->simple_select("admin_ips", "*", "allow_disallow=1", array("order_by" => "username", "order_dir" => "ASC"));
$table = new TABLE;
$table->construct_header("Username");
$table->construct_header("IP Address");
$table->construct_header("Manage", array("colspan" => 2));
$table->construct_row();
while($whitelist = $db->fetch_array($query))
{
    if(!$whitelist['username'])
    {
        $whitelist['username'] = "Unknown";
    }
    $table->construct_cell($whitelist['username']);
    $table->construct_cell($whitelist['ipaddress']);
    $removelink = "index.php?module=tools-admin_ips&action=deleteip&id=" . $whitelist['id'] . "&amp;my_post_key=" . $mybb->post_code;
    $table->construct_cell("<a href=\"$removelink\">Remove IP</a>");
    $blocklink = "index.php?module=tools-admin_ips&action=blockip&id=" . $whitelist['id'] . "&amp;my_post_key=" . $mybb->post_code;
    $table->construct_cell("<a href=\"$blocklink\">Block IP</a>");
    $table->construct_row();
}
$table->output("Allowed IP Addresses");

$table->construct_header("Username");
$table->construct_header("IP Address");
$table->construct_header("Manage");
$table->construct_row();

$query = $db->simple_select("admin_ips", "*", "allow_disallow=0", array("order_by" => "username", "order_dir" => "ASC"));
if($db->num_rows($query) == 0)
{
    $table->construct_cell("There are no results to display.", array("colspan" => 3));
    $table->construct_row();
}
while($blacklist = $db->fetch_array($query))
{
    if(!$blacklist['username'])
    {
        $blacklist['username'] = "Guest";
    }
    $table->construct_cell($blacklist['username']);
    $table->construct_cell($blacklist['ipaddress']);
    $removelink = "index.php?module=tools-admin_ips&action=deleteip&id=" . $blacklist['id'] . "&amp;my_post_key=" . $mybb->post_code;
    $table->construct_cell("<a href=\"$removelink\">Delete</a>");
    $table->construct_row();
}
$table->output("Disallowed IP Addresses");

// Now a form to add by IP
$form = new DefaultForm("index.php?module=tools-admin_ips&action=addip", "post", "add_by_ip", 0, "add_by_ip");
$form_container = new FormContainer("Add IP");
$form_container->output_row("IP Address <em>*</em>", "Enter the IP Address", $form->generate_text_box("ipaddress", $mybb->input['ipaddress']), "ipaddress");
$form_container->output_row("What should be done?", "Select Allow for this IP to be added.  Disallow makes this IP unable to log in.", $form->generate_select_box("allow_disallow", array("1" => "Allow", "0" => "Disallow"), $mybb->input['allow_disallow']), "allow_disallow");
$form_container->end();
$form->output_submit_wrapper(array($form->generate_submit_button("Add IP")));
$form->end();

// Now a form to do by username instead
$form = new DefaultForm("index.php?module=tools-admin_ips&amp;action=addusername", "post", "add_by_username", 0, "add_by_username");
$form_container = new FormContainer("Add Username");
$form_container->output_row("Username <em>*</em>", "Enter the username.", $form->generate_text_box("ipusername", $mybb->input['ipusername']), "ipusername");
$form_container->output_row("What should be done?", "Select Allow for this member's IP to be added.  Disallow makes this IP unable to log in.", $form->generate_select_box("allow_disallow", array("1" => "Allow", "0" => "Disallow"), $mybb->input['allow_disallow']), "allow_disallow");
$form_container->end();
$form->output_submit_wrapper(array($form->generate_submit_button("Add Username")));
$form->end();

$page->output_footer();

?>
