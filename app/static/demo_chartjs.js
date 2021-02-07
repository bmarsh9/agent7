function draw_score_progress() {
 new Chart(document.getElementById("chart1"), {
  type: 'line',
  data: {
    labels: ["8/2019","9/2019","10/2019","11/2019","12/2019","1/2020","2/2020","3/2020"],
    datasets: [{ 
        data: [40,64,76,88,110,105,120,130],
        label: "Agent",
        borderColor: "#3e95cd",
        fill: false
      }, { 
        data: [0,10,30,30,35,120,200,400],
        label: "Active Directory",
        borderColor: "#8e5ea2",
        fill: false
      }, { 
        data: [60,100,90,80,130,155,170,170],
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
function draw_current_scores_polar() {
 new Chart(document.getElementById("chart2"), {
    type: 'polarArea',
    data: {
      labels: ["Agent","Active Directory","Watcher"],
      datasets: [
        {
          backgroundColor: ["#3e95cd", "#8e5ea2","#3cba9f"],
          data: [130,400,170]
        }
      ]
    },
    options: {
      maintainAspectRatio: false,
      animation: {
        duration: 3000
      },
      legend: {
        labels: {
          fontColor:"white"
        }
      },
      scale: {
        ticks: {
          backdropColor: '#525f7f'
        }
      }
    }
 });
}

function draw_current_scores_radar() {
 new Chart(document.getElementById("chart2"), {
    type: 'radar',
    data: {
      labels: ["Agent","Active Directory","Watcher"],
      datasets: [
        {
          label: "Scores",
          fill: true,
          backgroundColor: "rgba(255,99,132,0.2)",
          borderColor: "rgba(255,99,132,1)",
          pointBorderColor: "#fff",
          pointBackgroundColor: "rgba(255,99,132,1)",
          pointBorderColor: "#fff",
          data: [130,400,170]
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

function draw_current_scores(compare_label="Industry Average") {
 new Chart(document.getElementById("chart2"), {
    type: 'bar',
    data: {
      labels: ["Agent","Active Directory","Watcher"],
      datasets: [
        {
          label: "Current Score",
          backgroundColor: "#3e95cd",
          data: [130,400,170]
        }, {
          label: compare_label,
          backgroundColor: "lightgray",
          data: [150,300,150]
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

function draw_mixed_chart(selector="chart3") {
 new Chart(document.getElementById(selector), {
    type: 'bar',
    data: {
      labels: ["Agent","Active Directory","Watcher"],
      datasets: [{
          label: "Last Month",
          type: "line",
          borderColor: "#8e5ea2",
          data: [150,300,150],
          fill: false
        }, {
          label: "Next Goal",
          type: "line",
          borderColor: "#3e95cd",
          data: [170,430,200],
          fill: false
        }, {
          label: "Current Score",
          type: "bar",
          backgroundColor: "rgba(216,216,216,0.2)",
          data: [130,400,170]
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
