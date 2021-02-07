function d3map_init(selector,citydata) {
var cities = citydata

var h = $(selector)
var width = h.width();
var height = 550;
//haaaaaa

var projection = d3.geo.mercator()
    .center([40,34]) //long and lat starting position

var svg = d3.select("#map").append("svg")
    .attr("width", width)
    .attr("height", height);   

var path = d3.geo.path()
    .projection(projection);

var g = svg.append("g");

// load and display the world and locations
d3.json("/static/assets/world-110m2.json", function(error, topology) {

var world = g.selectAll("path")
                                .data(topojson.object(topology, topology.objects.countries).geometries)
                                .enter()
                                .append("path")
                                .style("fill", "grey")
                                .style("opacity", 0.6)
                                .attr("d", path)


// add city location circles
var locations = g.selectAll("circle")
                               .data(cities)
                               .enter()
                               .append("circle")
                               .attr("cx", function(d) {return projection([d.lon, d.lat])[0];})
                               .attr("cy", function(d) {return projection([d.lon, d.lat])[1];})
                               .attr("r", 4)
                               .style("fill", "blue")
                               .style("opacity", 0.6)
                               ;

});
//zoom and pan functionality
var zoom = d3.behavior.zoom()
    .on("zoom",function() {
        g.attr("transform","translate("+
            d3.event.translate.join(",")+")scale("+d3.event.scale+")");
        g.selectAll("path")
            .attr("d", path.projection(projection));
  });
svg.call(zoom);
}

