document.querySelector('form').addEventListener('submit', async function (e) {
    e.preventDefault();
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const response = await axios.post('/api/auth/register', {name, email, password});
        alert("Dang ky thanh cong");
    } catch (error) {
        console.error(error);
        alert(error.response.data.message)
    }
});