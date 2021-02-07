function draw_historial_risk(selector,labels,data1,data2,data3) {
 new Chart(document.getElementById(selector), {
  type: 'line',
  data: {
    labels: labels,
    datasets: [{ 
        data: data1,
        label: "Agent",
        borderColor: "#3e95cd",
        fill: false
      }, { 
        data: data2,
        label: "Active Directory",
        borderColor: "#8e5ea2",
        fill: false
      }, { 
        data: data3,
        label: "Watcher",
        borderColor: "#3cba9f",
        fill: false
      }
    ]
  },
  options: {
    maintainAspectRatio: false,
    animation: {
      duration: 3000
    },
    scales:{
      xAxes:[{ticks:{fontColor:"white"}}],
      yAxes:[{ticks:{fontColor:"white"}}],
    },
    legend: {
      labels: {
        fontColor:"white"
      }
    },
  }
 });
}

function draw_comparison_risk(selector,data1,data2,data3,data4,data5) {
 new Chart(document.getElementById(selector), {
    type: 'horizontalBar',
    data: {
      labels: ["6 month","Last month","Last week","Current","Clients"],
      datasets: [
        {
          label: "6 month",
          backgroundColor: "#515A5A",
          data: [data1]
        }, {
          label: "Last month",
          backgroundColor: "#7F8C8D",
          data: [data2]
        }, {
          label: "Last week",
          backgroundColor: "#B2BABB",
          data: [data3]
        }, {
          label: "Current",
          backgroundColor: "#E74C3C",
          data: [data4]
        }, {
          label: "Clients",
          backgroundColor: "#3498DB",
          data: [data5]
        }
      ]
    },
    options: {
      scales:{
        xAxes:[{ticks:{fontColor:"white",beginAtZero: true}}],
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
