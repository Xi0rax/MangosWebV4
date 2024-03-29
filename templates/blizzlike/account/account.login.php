<br>
<?php builddiv_start(1, $lang['login']);

// If the user is not logged in, we need to check
// first if there is an error (IE: Login does not equal 1)
if($Account->isLoggedIn() == FALSE)
{
	if(isset($Login) && $Login['code'] != 1)
	{
		if($Login == 0) # Username not found
		{
			output_message('error', $lang['username_doesnt_exist']);
		}
		elseif($Login == 2) # some params emtpy
		{
			output_message('validation', $lang['some_params_empty']);
		}
		elseif($Login == 3) # Password is wrong
		{
			output_message('validation', $lang['wrong_password']);
		}
		elseif($Login == 4) # Account Banned
		{
			output_message('error', $lang['account_banned']);
		}
		elseif($Login == 5) # Account not activated
		{
			output_message('warning', $lang['account_not_activated']);
		}
	}
?>
    <table align="center" width="100%">
		<tr>
			<td align="center" width="100%">
				<form method="post" action="?p=account&amp;sub=login&amp;exec=login">
					<div style="border:background:none;margin:1px;padding:6px 9px 6px 9px;text-align:center;width:70%;">
						<b><?php echo $lang['username'] ?></b> <input type="text" size="26" style="font-size:11px;" name="login">
					</div>
					<div style="border:background:none;margin:1px;padding:6px 9px 6px 9px;text-align:center;width:70%;">
						<b><?php echo $lang['password'] ?></b> <input type="password" size="26" style="font-size:11px;" name="pass">
					</div>
					<div style="background:none;margin:1px;padding:6px 9px 0px 9px;text-align:center;width:70%;">
						<input type="image" src="<?php echo $Template['path']; ?>/images/buttons/button-login.gif" class="button" style="font-size:12px;" value="<?php echo $lang['change'];?>">
					</div>
				</form>
			</td>
		</tr>
	</table>
<?php
}
else
{
	output_message('success','<b>'.$lang['welcome'].' '.(isset($Login['username']) ? $Login['username'] : $user['username']).'! '.$lang['now_logged_in'].'</b><meta http-equiv=refresh content="4;url=/">');
}
?>
<?php builddiv_end() ?>