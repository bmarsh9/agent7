$(document).ready(function (url,operation){
   $.noConflict();
   // Draw Table
   var table = $('#example').DataTable({
      'ajax': {
         'url': '/api/agent/data/users?as_datatables=true&inc_fields=id,email,active'
      },
      'columnDefs': [
      {
         'targets': 0,
         'width': "5%"
      },
      { // Icon for Actions
         'targets': -1,
         'searchable': false,
         'orderable': false,
         'width': "10%",
         'data': null,
         'render': function (data, type, full, meta){
               return '<td class="text-right"><button type="button" id="tester" rel="tooltip" class="btn btn-primary btn-link btn-sm btn-icon " data-original-title="Refresh" title=""><i class="tim-icons icon-settings"></i></button><button type="button" rel="tooltip" class="btn btn-warning btn-link btn-sm " data-original-title="Delete" title=""><i class="tim-icons icon-simple-remove"></i></button></td>'
         }
      },
      { // Icon for Active/Disabled
         'targets': -2,
         'data': null,
         'searchable': false,
         'orderable': false,
         'width': "1%",
         'render': function (data, type, full, meta){
             var active = data[data.length-1];
             console.log(active);
             if ( active ) {
               return '<td class="text-right"><button type="button" rel="tooltip" class="btn btn-success btn-link btn-sm btn-icon " data-original-title="Refresh" title=""><i class="tim-icons icon-check-2"></i></button></td>'
             } else {
               return '<td class="text-right"><button type="button" rel="tooltip" class="btn btn-warning btn-link btn-sm btn-icon " data-original-title="Refresh" title=""><i class="tim-icons icon-button-power"></i></button></td>'
             }
         }
      }]
   });
   // Settings Icon
   $('#example tbody').on('click', 'i.tim-icons.icon-settings', function(e) {
     var $row = $(this).closest('tr');
     var data = table.row($row).data();
     jQuery('#editModal').modal('show');
     jQuery('#editModal').on('shown.bs.modal', function (e) {
          $(e.currentTarget).find('input[name="id"]').val(data[0]);
          $(e.currentTarget).find('input[name="dataEmail"]').val(data[1]);
          $(e.currentTarget).find('input[name="dataActive"]').val(data[2]);
     });
   });
   // Delete
   $('#example tbody').on('click', 'i.tim-icons.icon-simple-remove', function(e) {
     var $row = $(this).closest('tr');
     var data = table.row($row).data();
     jQuery('#deleteModal').modal('show');
     jQuery('#deleteModal').on('shown.bs.modal', function (e) {
          $(e.currentTarget).find('input[name="id"]').val(data[0]);
     });
   });
   // Active/Disabled
   $('#example tbody').on('click', 'i.tim-icons.icon-check-2, i.tim-icons.icon-button-power', function(e) {
     var $row = $(this).closest('tr');
     var data = table.row($row).data();
     var active = 1 - data[2];
     $.ajax({
        type: "POST",
        url: "/api/agent/data/users?crud=update&filter=id,eq,"+data[0],
        data : JSON.stringify({"active":active}),
        contentType: 'application/json',
        success: function(result) {
            $.notify({
              // options
              message: result["message"]
            },{
              // settings
              type: result["type"]
            });
            setTimeout(function() {
//                location.reload();
                table.ajax.reload();
                console.log("reloaded");
            }, 500);
        },
        error: function(result) {
            $.notify({
              // options
              message: 'An Error occurred. Please contact an Administrator.'
            },{
              // settings
              type: 'danger'
            });
        }
     });
   });
   // Button to submit the add request
   $("button#addModal").click(function(e) {
           e.preventDefault();
           $.ajax({
             type: "POST",
             url: "/api/agent/data/users?crud=insert",
             data : JSON.stringify({"email":$('#add-form-email').val(),"password":$('#add-form-password').val(),"active":$('#add-form-active').val()}),
             contentType: 'application/json',
             success: function(result) {
               $.notify({
                 // options
                 message: result["message"]
               },{
                 // settings
                 type: result["type"]
               });
               setTimeout(function() {
                   table.ajax.reload();
                   console.log("reloaded");
               }, 500);
             },
             error: function(result) {
               $.notify({
                  // options
                 message: 'An Error occurred. Please contact an Administrator.'
               },{
                 // settings
                 type: 'danger'
               });
             }
           });
           jQuery('#addModal').modal("hide");
   });
   // Button to submit the edit request
   $("button#editModal").click(function(e) {
           e.preventDefault();
           $.ajax({
             type: "POST",
             url: "/api/agent/data/users?crud=update&filter=id,eq,"+$('#edit-form-id').val(),
             data : JSON.stringify({"email":$('#edit-form-email').val(),"active":$('#edit-form-active').val()}),
             contentType: 'application/json',
             success: function(result) {
               $.notify({
                 // options
                 message: result["message"]
               },{
                 // settings
                 type: result["type"]
               });
               setTimeout(function() {
                   table.ajax.reload();
                   console.log("reloaded");
               }, 500);
             //  $('#editModal').modal("hide");
             },
             error: function(result) {
               $.notify({
                  // options
                 message: 'An Error occurred. Please contact an Administrator.'
               },{
                 // settings
                 type: 'danger'
               });
             }
           });
           jQuery('#editModal').modal("hide");
   });
   // Button to submit the delete request
   $("button#deleteModal").click(function(e) {
           e.preventDefault();
           $.ajax({
             type: "POST",
             url: "/api/agent/data/users?crud=delete&filter=id,eq,"+$('#delete-form-id').val(),
             contentType: 'application/json',
             success: function(result) {
               $.notify({
                 // options
                 message: result["message"]
               },{
                 // settings
                 type: result["type"]
               });
               setTimeout(function() {
                   table.ajax.reload();
                   console.log("reloaded");
               }, 500);
             },
             error: function(result) {
               $.notify({
                  // options
                 message: 'An Error occurred. Please contact an Administrator.'
               },{
                 // settings
                 type: 'danger'
               });
             }
           });
           jQuery('#deleteModal').modal("hide");
       });
   // Check data response for any errors
   table.on( 'xhr', function () {
    var json = table.ajax.json();
    //console.log(json);
    if (json["result"] === false) {
        $.notify({
            // options
            message: json["message"]
            },{
            // settings
            type: json["type"]
        });
    };
   });
});
