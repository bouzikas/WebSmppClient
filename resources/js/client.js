
$(document).ready(function(){
	$('#connBtn').click(function() {
		var smsc_id = $('#smsc_id').val();
		var host = $('#host').val();
		var sys_type = $('#sys_type').val();
		var username = $('#username').val();
		var passwd = $('#passwd').val();
		var port = $('#port').val();
		var receiver_port = $('#receiver_port').val();
						
		connect(smsc_id, host, sys_type, username, passwd, port, receiver_port);
	});
				  
	function connect(smsc_id, host, sys_type, username, passwd, port, receiver_port)
	{
		var url = "";
		
		// A temporary solution will be removed
		// after implemented the login process.
		url += "connect?password=password&";
		url += "smsc_id="+smsc_id+"&";
		url += "host="+host+"&";
		url += "sys_type="+sys_type+"&";
		url += "username="+username+"&";
		url += "passwd="+passwd+"&";
		url += "port="+port+"&";
		url += "receiver_port="+receiver_port;
				  
		$.ajax({
			url: url,
			cache: false,
			dataType: "json",
			type: "POST",
			beforeSend: function() {
			   
			},
			success: function(data) {
				
			}
		});
	}
});