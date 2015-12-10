
$(document).ready(function(){
	$('#connBtn').click(function() {
		var smsc_id = $('#smsc_id').val();
		var host = $('#host').val();
		var sys_type = $('#sys_type').val();
		var username = $('#username').val();
		var passwd = $('#passwd').val();
		var port = $('#port').val();
		var receiver_port = $('#receiver_port').val();
		var transport_type = $('#transport_type').val();
						
		connect(smsc_id, host, sys_type, username, passwd, port, receiver_port, transport_type);
	});
				  
	function connect(smsc_id, host, sys_type, username, passwd, port, receiver_port, transport_type)
	{
		var url = "";
		
		if (transport_type == 0) {			// Transmitter
			receiver_port = 0;
		}
		else if (transport_type == 1) {		// Receiver
			port = 0;
			transport_type = 0;
		}
		else if (transport_type == 2) {		// Transmitter
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
               
                  $('#connBtn').attr('disabled', true);
                  $('#discBtn').attr('disabled', false);
                  $('#conn_box .panel-body').append(alert);
               }
			}
		});
	}
				  
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
				
				  
    function conn_status()
    {
        $.ajax({
            url: url,
            cache: false,
            dataType: "json",
            type: "GET",
            beforeSend: function() {
               
            },
            success: function(data) {
               
            }
        });
    }
});