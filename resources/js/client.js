
$(document).ready(function(){
				  
	$('#conn_box input[type="text"], #conn_box input[type="password"], #conn_box select').blur(function() {
		enableDisableConnectButton();
	});
	
	$('#conn_box select').change(function() {
		enableDisableConnectButton();
	});
				  
	$('#connBtn').click(function() {
		var smsc_id = $('#smsc_id').val();
		var host = $('#host').val();
		var sys_type = $('#sys_type').val();
		var username = $('#username').val();
		var passwd = $('#passwd').val();
		var port = $('#port').val();
		var receiver_port = $('#receiver_port').val();
		var conn_type = $('#transport_type').val();
						
		connect(smsc_id, host, sys_type, username, passwd, port, receiver_port, conn_type);
	});
				  
	$('#discBtn').click(function() {
		var url = "";
		url += "disconnect?password=password";
						
		$.ajax({
			url: url,
			cache: false,
			dataType: "json",
			type: "GET",
			beforeSend: function() {
			   $('#discBtn').attr('disabled', true);
			   $('.alert').hide().remove();
			},
			success: function(data) {
			   if (data.error == 1) {
				   var alert = '';
				   
				   alert += '<div class="alert alert-danger">';
				   alert += '<strong>SMSC:</strong> '+data.status;
				   alert += '</div>';
				   
				   $('#connBtn').attr('disabled', false);
				   $('#conn_box .panel-body').append(alert);
			   } else {
				   var alert = '';
				   
				   alert += '<div class="alert alert-success">';
				   alert += '<strong>SMSC:</strong> '+data.status;
				   alert += '</div>';
				   
				   $('#connBtn').attr('disabled', false);
				   $('#discBtn').attr('disabled', true);
				   $('#conn_box .panel-body').append(alert);
			   }
			}
		});
	});
				  
	$('#sendBtn').click(function() {
		var sender = $('#sender').val();
		var receiver = $('#receiver').val();
		var data_coding = $('#data_coding').val();
		var message = $('#message').val();
				
		sendMessage(sender, receiver, data_coding, message);
    });
				  
	
	
	function connect(smsc_id, host, sys_type, username, passwd, port, receiver_port, conn_type)
	{
		var url = "";
		
		if (conn_type == 0) {			// Transmitter
			receiver_port = 0;
		} else if (conn_type == 1) {		// Receiver
			port = 0;
			transport_type = 0;
		} else if (conn_type == 2) {		// Transmitter
			transport_type = 1;
		}
				  
		// A temporary solution will be removed
		// after implemented the login process.
		url += "connect?password=password&";
		url += "smsc_id="+smsc_id+"&";
		url += "host="+host+"&";
		url += "sys_type="+sys_type+"&";
		url += "username="+username+"&";
		url += "passwd="+passwd+"&";
		url += "port="+port+"&";
		url += "receiver_port="+receiver_port+"&";
		url += "transport_type="+transport_type;
				  
		$.ajax({
			url: url,
			cache: false,
			dataType: "json",
			type: "POST",
			beforeSend: function() {
               $('#connBtn').attr('disabled', true);
               $('.alert').hide().remove();
			},
			success: function(data) {
			   var alert = '';
			   
               if (data.error == 1) {
                   alert += '<div class="alert alert-danger">';
                   $('#connBtn').attr('disabled', false);
               } else {
                   alert += '<div class="alert alert-success">';
               
                   $('#connBtn').attr('disabled', true);
                   $('#discBtn').attr('disabled', true);
			   
			       conn_status();
               }
			   alert += '<strong>SMSC:</strong> <span class="stat">'+data.status+'</span>';
			   alert += '</div>';
			   
			   $('#conn_box .panel-body').append(alert);
			}
		});
	}
	
	function sendMessage(sender, receiver, data_coding, message)
	{
		var url = "";
		
		url += "send_message?password=password&";
		url += "sender="+sender+"&";
		url += "receiver="+receiver+"&";
		url += "data_coding="+data_coding+"&";
		url += "message="+message;
						  
		$.ajax({
			url: url,
			cache: false,
			dataType: "json",
			type: "POST",
			beforeSend: function() {
               $('#sendBtn').attr('disabled', true);
			},
			success: function(data) {
				$('#sendBtn').attr('disabled', false);
			}
		});
	}			  
	
	function enableDisableConnectButton()
	{
		if (connectButtonShouldEnabled()) {
			$('#connBtn').attr('disabled', false);
		} else {
			$('#connBtn').attr('disabled', true);
		}
	}
	
	function connectButtonShouldEnabled()
	{
		var enableConnectButton = true;
		$('#conn_box input[type="text"], #conn_box input[type="password"], #conn_box select').each(function() {
			if ($(this).attr('id') == "port" || $(this).attr('id') == "receiver_port") {
				enableConnectButton = transportPortsAreValid();
			} else if ($(this).val() == "") {
				enableConnectButton = false;
			}
		});
		
		return enableConnectButton;
	}
	
	function transportPortsAreValid()
	{
		var valid = false;
		var conn_type = $('#conn_box select').val();
				
		if (conn_type == 0) {				// Transmitter
			valid = ($('#port').val().length != 0);
		} else if (conn_type == 1) {		// Receiver
			valid = ($('#receiver_port').val().length != 0);
		} else if (conn_type == 2) {		// Transmitter
			valid = ($('#port').val().length != 0 && $('#receiver_port').val().length != 0);
		}
		
		return valid;
	}		
				  
    function conn_status()
    {
        $.ajax({
            url: "conn_status?password=password",
            cache: false,
            dataType: "json",
            type: "GET",
            success: function(data) {
			   if (data.error == 1) {
			       conn_status();
			   } else {
			       $('#discBtn').attr('disabled', false);
			       $('#sendBtn').attr('disabled', false);
			       $('#conn_box .panel-body .alert .stat').html(data.status);
			   }
            }
        });
    }
});