
$(document).ready(function(){
	$('#connBtn').click(function() {
		var smsc_id = $('#smsc_id').val();
		var host = $('#host').val();
		var sys_type = $('#sys_type').val();
		var username = $('#username').val();
		var port = $('#port').val();
		var receiver_port = $('#receiver_port').val();
						
		connect(smsc_id, host, sys_type, username, passwd, port, receiver_port);
	});
				  
	function connect(smsc_id, host, sys_type, username, passwd, port, receiver_port)
	{
		$.ajax({
			url: "connect?password=password",
			cache: false,
			data: ({
				   smsc_id: smsc_id, host: host, sys_type: sys_type,
				   username: username, passwd: "password",
				   port: port, receiver_port: receiver_port
			}),
			dataType: "json",
			type: "POST",
			beforeSend: function() {
			   
			},
			success: function(data) {
				
			}
		});
	}
});