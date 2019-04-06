package springboot.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private ImplementacaoUserDetailsService implementacaoUserDetailsService;
	
	@Autowired
	private DataSource dataSource;

	@Override //Configura as solicitações de acesso por Http
	protected void configure(HttpSecurity http) throws Exception {
		
		 http.csrf()
		.disable()
		.authorizeRequests()
		.antMatchers(HttpMethod.GET, "/").permitAll() // Qualquer usuario acessa a página inicial 
		.antMatchers(HttpMethod.GET, "/cadastropessoa").hasAnyRole("ADMIN")
		.anyRequest().authenticated()
		.and().formLogin().permitAll() // Permite qualquer usuario
		.loginPage("/login")
		.defaultSuccessUrl("/cadastropessoa")
		.failureUrl("/login?error=true")
		.and().logout().logoutSuccessUrl("/login") // Mapeia URL de logout e invalida usuario autenticado
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
	}
	
	@Override // Cria a autenticação do usuário com o banco de dados ou em memória
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		
		auth.userDetailsService(implementacaoUserDetailsService)
		.passwordEncoder(new BCryptPasswordEncoder());
		
	/*	auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
		.withUser("charles")
		.password("$2a$10$mEgwmqCY69i85yiGN1fJ4.6H6bq9ccCYytVVZnYjNP3kKFuSZ/It2")
		.roles("ADMIN"); */
	}
	
	@Override // Ignora URL específicas
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/materialize/**");
		
	}
}
