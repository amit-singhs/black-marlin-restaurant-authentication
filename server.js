const app = require('./api/app');
const PORT = process.env.PORT || 3000;
app.get('/', (req, res) => {
  res.send('Hello Universe !');
});
app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}/api/`);
}); 