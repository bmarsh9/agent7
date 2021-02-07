function draw_risk_bars(selector,data1,data2) {
 new Chart(document.getElementById(selector), {
    type: 'bar',
    data: {
      labels: ["Total","Agent","Active Directory","Watcher"],
      datasets: [
        {
          label: "Last Month",
          backgroundColor: "lightgray",
          data: data1
        }, {
          label: "Current Scores",
          backgroundColor: "#3e95cd",
          data: data2
        }
      ]
    },
    options: {
      scales:{
        xAxes:[{ticks:{fontColor:"white"}}],
        yAxes:[{ticks:{fontColor:"white"}}],
      },
      maintainAspectRatio: false,
      animation: {
        duration: 3000
      },
      legend: {
        labels: {
          fontColor:"white"
        }
      },
    }
 });
}
