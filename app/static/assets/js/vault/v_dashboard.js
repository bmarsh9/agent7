function vault_dash(selector,url) {
    $.ajax({
         type: "GET",
         url: url,
         contentType: 'application/json',
         success: function(result) {
            new Chart(document.getElementById(selector), {
                type: 'bar',
                data: {
                  labels: ["Unmanaged","Managed"],
                  datasets: [
                    {
                      backgroundColor: ["#c45850","#3e95cd"],
                      data: result["data"]
                    }
                  ]
                },
                options: {
                  scales:{
                    "xAxes":[{"ticks":{"fontColor":"white","beginAtZero": true}}],
                    "yAxes":[{"ticks":{"fontColor":"white","beginAtZero": true}}],
                  },
                  animation: {"duration":3000},
                  title: {
                    display: false,
                    text: 'Managed v Unmanaged'
                  },
                   responsive: true,
                   maintainAspectRatio: false,
                   legend:{
                     display: false
                   }
                }
            });
         },
         error: function(result) {
            console.log(result);
         }
    });
}
