import React, { Component } from 'react';
import {upgPreloginSrp} from './srp/srp_client';
import './App.css';

class App extends Component {
  constructor(props) {
    super(props);
    this.state={
      login: '',
      password: '',
      prelogindata: '',
      result: ''
    }
  }

  loginChanged = (event) => {
    this.setState({login: event.target.value});
  }

  passwordChanged = (event) => {
    this.setState({password: event.target.value});
  }

  preloginChanged = (event) => {
    this.setState({prelogindata: event.target.value});
  }

  handleSubmit = (event) => {
    const login=this.state.login;
    const password=this.state.password;
    const prelogin=this.state.prelogindata;
    const result=upgPreloginSrp(login,password,prelogin);
    this.setState({result: result});
    event.preventDefault();
  }

  render() {
    return (
      <div>
        <form onSubmit={this.handleSubmit}>        
          Login:<input id="login" type="text" onChange={this.loginChanged} value={this.state.login}/>
          Password:<input id="password" type="text" onChange={this.passwordChanged} value={this.state.password}/><br></br>
          PreLoginResponse:<textarea className="App-textarea" id="prelogin" type="text" onChange={this.preloginChanged} value={this.state.prelogindata}/><br></br>
          <input type="submit" value="Go"/><br></br><br></br>
          Result:<textarea className="App-textarea" id="result" type="text" value={this.state.result}/><br></br>
        </form>
      </div>
    );
  }
}

export default App;
