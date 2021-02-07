function sparkline_init(selector,url,bar=true,color="#00f2c3",fill="rgba(0,242,195,0.2)") {
  $.ajax({
         type: "GET",
         url: url,
         contentType: 'application/json',
         success: function(result) {
           var config = {
             "height":25,
             "width":"100%",
           }
           if (bar) {
               config["type"] = "bar"
               config["barColor"] = color
               config["barWidth"] = 10
               config["chartRangeMax"] = 12
           } else {
               config["lineColor"] = color
               config["fillColor"] = fill
           };

           $(selector).sparkline(result["data"], config);
         },
         error: function(result) {
            console.log(result);
         }
   });
}

