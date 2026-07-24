const RENDER_URL = "https://sageshield-q8pv.onrender.com/api/analyze";

document.getElementById('analyzeBtn').addEventListener('click', async () => {
  const emailText = document.getElementById('emailText').value.trim();
  const resultDiv = document.getElementById('result');

  if (!emailText) {
    alert("Please paste an email first.");
    return;
  }

  try {
    const response = await fetch(RENDER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ emailText })
    });

    const data = await response.json();

    if (response.ok) {
      document.getElementById('heartline').innerText = data.heartline;
      document.getElementById('verdict').innerText = data.verdict;
      document.getElementById('message').innerText = data.message;
      document.getElementById('score').innerText = data.score;

      const reasonsUl = document.getElementById('reasons');
      reasonsUl.innerHTML = '';
      if (data.found_words.length > 0) {
        data.found_words.forEach(word => {
          const li = document.createElement('li');
          li.innerText = `Suspicious signal found: ${word}`;
          reasonsUl.appendChild(li);
        });
      } else {
        reasonsUl.innerHTML = '<li>No common phishing words or suspicious links were found.</li>';
      }

      document.getElementById('highlighted').innerHTML = data.highlighted_email;
      resultDiv.style.display = 'block';
    } else {
      alert(data.error || 'An error occurred.');
    }
  } catch (err) {
    alert('Could not connect to backend server. Make sure Python/Flask is running!');
  }
});
