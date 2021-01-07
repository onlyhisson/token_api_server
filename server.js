const express = require("express");
const bodyParser = require("body-parser");

require('dotenv').config();
const PORT = process.env.PORT;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.disable("x-powered-by");

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});

app.use("/auth", require(`${__dirname}/route/auth`));

app.get("/", function (req, res) {
  res.send("Hello XY----");
});

app.listen(PORT, function () {
  console.log('==============================');
  console.log("* Token API SERVER Started");
  console.log("* PORT : ", PORT);
  console.log('==============================');
});

