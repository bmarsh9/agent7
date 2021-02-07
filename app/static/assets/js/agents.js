$(document).ready(function (){
   $.noConflict();
   // Draw Table
   var table = $('#example').DataTable({
      'ajax': {
         'url': '/api/raw/dbagenthost?as_schema=true&exc_fields=agent_id,architecture,cpu_count,os_build,memory'
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
      { // Icon for Enabled/Disabled
         'targets': -2,
         'data': null,
         'searchable': false,
         'orderable': false,
         'width': "1%",
         'render': function (data, type, full, meta){
             var enabled = data[data.length-1];
             console.log(enabled);
             if ( enabled === true ) {
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
          $(e.currentTarget).find('input[name="dataGroupname"]').val(data[1]);
          $(e.currentTarget).find('input[name="dataConsole"]').val(data[2]);
          $(e.currentTarget).find('input[name="dataPort"]').val(data[3]);
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
   // Enabled/Disabled
   $('#example tbody').on('click', 'i.tim-icons.icon-check-2, i.tim-icons.icon-button-power', function(e) {
     var $row = $(this).closest('tr');
     var data = table.row($row).data();
     $.ajax({
        type: "POST",
        url: "/api/raw/dbuser?crud=update&filter=id,eq,"+data[0],
        data : JSON.stringify({"enabled":!data[4]}),
        contentType: 'application/json',
        success: function(result) {
            $.notify({
              // options
              message: 'Record Updated. Refreshing table.'
            },{
              // settings
              type: 'info'
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
           var isTrueSet = ($('#add-form-enabled').val() === 'True');
           e.preventDefault();
           $.ajax({
             type: "POST",
             url: "/api/settings/agents/add",
             data : JSON.stringify({"groupname":$('#add-form-groupname').val(),"console":$('#add-form-console').val(),"port":$('#add-form-port').val(),"enabled":isTrueSet}),
             contentType: 'application/json',
             success: function(result) {
               $.notify({
                 // options
                 message: 'Record Added. Refreshing table.'
               },{
                 // settings
                 type: 'info'
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
           var isTrueSet = ($('#edit-form-enabled').val() === 'True');
           e.preventDefault();
           $.ajax({
             type: "POST",
             url: "/api/settings/agents/edit",
             data : JSON.stringify({"groupname":$('#add-form-groupname').val(),"console":$('#add-form-console').val(),"port":$('#add-form-port').val(),"enabled":isTrueSet}),
             contentType: 'application/json',
             success: function(result) {
               $.notify({
                 // options
                 message: 'Record Updated. Refreshing table.'
               },{
                 // settings
                 type: 'info'
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
             url: "/api/settings/agents/delete",
             data : JSON.stringify({"id":$('#delete-form-id').val()}),
             contentType: 'application/json',
             success: function(result) {
               $.notify({
                 // options
                 message: 'Record Deleted. Refreshing table.'
               },{
                 // settings
                 type: 'info'
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
});
