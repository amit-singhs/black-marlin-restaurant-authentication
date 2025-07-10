const app = require('./api/app');
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Local server running on http://localhost:${PORT}/api/`);
}); 