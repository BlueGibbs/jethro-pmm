<!DOCTYPE html>
<html lang="en">
<head>
	<?php include dirname(dirname(dirname(__FILE__))).'/templates/head.template.php' ?>
	<style>
		.sso-divider {
			display: flex;
			justify-content: center;
			padding: 30px 0 10px 0; /* Vertical spacing */
			font-size: 1.1em; 
		}
		.sso-buttons {
			display: flex;
			gap: 12px;
			align-items: center;
		}
		.sso-buttons a {
			display: block;
			text-decoration: none;
		}
		.sso-buttonseparator {
			width: 1px;
			height: 28px; 
			background: #858a9b; 
			margin: 0 4px;
		}
		.social-icon svg {
			width: 100%;
			height: 100%;
			display: block;
		}
	</style>
</head>
<body id="login">
	<form method="post" id="login-box" class="well disable-submit-buttons" action="<?php echo build_url(Array('logout' => NULL)); ?>" target="_top">
		<input type="hidden" name="login_key" value="<?php echo $login_key; ?>" />
		<?php 
		require_once 'include/size_detector.class.php';
		SizeDetector::printFormFields();
		?>
		<div id="login-header">
			<h1><?php echo ents(SYSTEM_NAME); ?></h1>
		</div>
		<div id="login-body" class="member-login">
			<noscript>
				<div class="alert"><strong>Error: Javascript is Disabled</strong><br />For Jethro to function correctly you must enable javascript, which is done most simply by lowering the security level your browser uses for this website</div>
			</noscript>
			<?php
			if (!empty($this->_error)) {
				echo '<div class="alert alert-error">'.$this->_error.'</div>';
			} else {
				echo ' <h3>Member Login</h3>';
			}
			?>
			<p>If we have your email address on file, you can log in here.</p>

			<div style="display:flex">
				<label style="margin: 5px 5px 0 0"><b>Email: </b></label>
				<input style="flex-grow:10" type="email" name="email" autofocus="autofocus" class="compulsory" value="<?php echo ents(array_get($_REQUEST, 'email', '')); ?>" placeholder="Email" />
			</div>

			<div id="member-login-options">
				<div id="member-login-left">
					<b>Got a password?</b><br />
					Enter your password to log in<br />
						<div class="input-append">
							<input type="password" name="password" value="" placeholder="Password"/><br>
							<input type="submit" name="login-request" class="btn" value="Log in" />
						</div>
				</div>
				<div id="member-login-right">
					<b>No password?<br>Forgot password?</b><br />
					<input class="btn" type="submit" name="password-request" value="Send activation link" />
				</div>
			</div>
			<div class="sso-divider">
				<b> - OR - </b>
			</div>
			<div>
				<h3>Social Login</h3>
				<p>Sign in with your social account if you have already linked it</p>
				<div class="sso-buttons">
					<!-- Generic login -->
					<a href="?oidc-login=1" class="social-icon generic" style="width: 40px; height: 40px;">
						<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
							<circle cx="100" cy="100" r="100" fill="#1877F2"/>
							<circle cx="100" cy="78" r="24" fill="white"/>
							<path
								d="M60 142C60 120.909 77.909 103 99 103H101C122.091 103 140 120.909 140 142V148H60V142Z"
								fill="white"
							/>
						</svg>
					</a>

					<!-- Separator -->
					<div class="sso-buttonseparator"></div>

					<!-- Google -->
					<div class="social-icon google" style="width: 40px; height: 40px;">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20.04 20.49"><defs><style>.cls-1{fill:#ed412d;}.cls-2{fill:#2da94f;}.cls-3{fill:#fdbd00;}.cls-4{fill:#3e82f7;}</style></defs><title>Asset 56</title><g id="Layer_2" data-name="Layer 2"><g id="Layer_1-2" data-name="Layer 1"><g id="HrcCOE.tif"><path class="cls-1" d="M17,2.54l-3,3A5.89,5.89,0,0,0,8.55,4.43,6,6,0,0,0,4.5,8.32L4.08,8,1.26,5.85c-.19-.15-.19-.15-.08-.36A10.17,10.17,0,0,1,6.31.79,9.63,9.63,0,0,1,9,.08a10.14,10.14,0,0,1,2.4,0,10.28,10.28,0,0,1,5.49,2.38l.1.09S17,2.55,17,2.54Z"/><path class="cls-2" d="M16.94,17.94a9.1,9.1,0,0,1-1.22.95A9.65,9.65,0,0,1,12,20.33a9,9,0,0,1-2.13.15,10.22,10.22,0,0,1-8.77-5.59c0-.08,0-.12.05-.18l3-2.33.28-.21.09.2A6,6,0,0,0,9,16.18a6.12,6.12,0,0,0,1.86.12,6.42,6.42,0,0,0,2.25-.56,5,5,0,0,0,.51-.27.11.11,0,0,1,.15,0l3.11,2.41Z"/></g><path class="cls-3" d="M4.49,8.35c-.68-.58-2-1.52-3.43-2.65a10.41,10.41,0,0,0,0,9.07l3.45-2.63A5.08,5.08,0,0,1,4.32,9C4.41,8.7,4.49,8.35,4.49,8.35Z"/><path class="cls-4" d="M10.32,8.35l-.05,4,5.43.07,0,.26a5.81,5.81,0,0,1-.73,1.49,4.62,4.62,0,0,1-1.31,1.26L16.84,18c.09-.08.23-.21.37-.36a7.46,7.46,0,0,0,.61-.69,10.59,10.59,0,0,0,.95-1.39A10.62,10.62,0,0,0,20,11.48a10.33,10.33,0,0,0,0-2.12c0-.36-.09-.67-.13-.9Z"/></g></g></svg>
					</div>

					<!-- apple -->
					<div class="social-icon apple" style="width: 40px; height: 40px;">
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20">
  <circle cx="10" cy="10" r="10" fill="#111111"/>

  <!-- Scaled + centered group -->
  <g transform="translate(3,2) scale(0.7)">
    <path d="M15.454,10.638A4.547,4.547,0,0,1,17.62,6.823a4.656,4.656,0,0,0-3.666-1.982c-1.543-.162-3.038.923-3.825.923s-2.011-.907-3.314-.883A4.882,4.882,0,0,0,2.706,7.387c-1.776,3.076-.451,7.6,1.251,10.083C4.809,18.687,5.8,20.047,7.106,20c1.273-.053,1.75-.813,3.288-.813,1.523,0,1.969.813,3.3.782,1.368-.022,2.229-1.223,3.05-2.452a10.071,10.071,0,0,0,1.395-2.841A4.393,4.393,0,0,1,15.454,10.638Z" fill="#fff"/>
    <path d="M12.942,3.207A4.475,4.475,0,0,0,13.966,0,4.552,4.552,0,0,0,11.02,1.525,4.261,4.261,0,0,0,9.969,4.617,3.77,3.77,0,0,0,12.942,3.207Z" fill="#fff"/>
  </g>
</svg>
					</div>

					<!-- facebook -->
					<div class="social-icon facebook" style="width: 40px; height: 40px;">
						<!-- created by svgstack.com | Attribution is required. --><svg viewBox="0 0 200 201" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M200 100.033C200 150.554 162.562 192.321 113.926 199.099C109.379 199.729 104.726 200.059 100.004 200.059C94.5521 200.059 89.1988 199.624 83.9856 198.783C36.3662 191.115 0 149.818 0 100.033C0 44.7877 44.7746 0 99.9965 0C155.218 0 200 44.7877 200 100.033Z" fill="#1877F2"/><path d="M113.926 80.3167V102.108H140.875L136.608 131.462H113.926V199.092C109.379 199.723 104.726 200.052 100.003 200.052C94.552 200.052 89.1986 199.617 83.9854 198.776V131.462H59.1317V102.108H83.9854V75.4454C83.9854 58.9041 97.3898 45.4888 113.933 45.4888V45.5028C113.982 45.5028 114.024 45.4888 114.073 45.4888H140.882V70.8755H123.365C118.158 70.8755 113.933 75.1019 113.933 80.3097L113.926 80.3167Z" fill="white"/></svg>
					</div>
				</div>
			</div>


			<table class="valign-top" style="width:100%">
				<tr>
					<td style="padding-right: 1em; padding-bottom: 0">
					</td>
					<td style="border-left: 2px solid #bbb; padding-left: 1em; padding-right: 0px; padding-bottom: 0; width: 1%; white-space: nowrap">
					</td>

				</tr>
			</table>
		<?php
		if (defined('MEMBER_LOGIN_NOTE') && MEMBER_LOGIN_NOTE) {
			echo '<p>'.MEMBER_LOGIN_NOTE.'</p>';
		}
		?>
		</div>
	</form>
</body>
</html>
