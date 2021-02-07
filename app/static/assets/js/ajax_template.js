function ajax_replace(selector=selector,url=url,method="POST",data={}) {
    console.log("here")
    $.ajax({
         type: method,
         url: url,
         data: data,
         contentType: 'application/json',
         success: function(result) {
            $.each(result["data"][0], function(key, value){
               $(selector).text(value);
            });
            //console.log(result["data"][0]);
         },
         error: function(result) {
            console.log(result);
         }
    });
}
