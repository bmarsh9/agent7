function gauge_init(selector,risk) {
      // Create chart
      var total = 100-risk
      var ctx = document.getElementsByClassName(selector);
      var chart = new Chart(ctx, {
          type:"doughnut",
          data: {
              labels : ["Score","Total"],
              datasets: [{
                  label: "Gauge",
                  data : [risk, total],
                  backgroundColor: [
                    "rgb(220,20,60)",
                    "rgb(250, 250, 250)",
                    "rgb(255, 205, 86)"
                  ]
              }]
          },
          options: {
              maintainAspectRatio: false,
              animation: {
                duration: 3000
              },
              circumference: Math.PI,
              rotation : Math.PI,
              cutoutPercentage : 90, // precent
              plugins: {
      					  datalabels: {
                    backgroundColor: 'lightgray',
      						  borderColor: '#ffffff',
                    color: function(context) {
      							  return context.dataset.backgroundColor;
      						  },
      						  font: function(context) {
                      var w = context.chart.width;
                      return {
                        size: w < 512 ? 18 : 20
                      }
                    },
                    align: 'start',
                    anchor: 'start',
                    offset: 10,
      						  borderRadius: 6,
      						  borderWidth: 2,
                    formatter: function(value, context) {
      							  var i = context.dataIndex;
                      var len = context.dataset.data.length - 1;
                      if(i == len){
                        return null;
                      }
      							  return "+"+value;
      						  }
                  }
              },
              legend: {
                  display: true,
                  labels: {
                    fontColor:"white"
                  },
              },
              tooltips: {
                  enabled: true
              }
          }
      });
}

