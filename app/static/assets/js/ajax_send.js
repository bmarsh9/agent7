function ajax_call(url=url,method="POST",data={}) {
    $.ajax({
         type: method,
         url: url,
         data: JSON.stringify(data),
         contentType: 'application/json',
         success: function(result) {
            console.log("success");
         },
         error: function(result) {
            console.log(result);
         }
    });
}
