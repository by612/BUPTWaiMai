# Day1
## 各模块概览

| **序号** | **名称**     | **说明**                                                     |
| -------- | ------------ | ------------------------------------------------------------ |
| 1        | sky-take-out | maven父工程，统一管理依赖版本，聚合其他子模块                |
| 2        | sky-common   | 子模块，存放公共类，例如：工具类、常量类、异常类等           |
| 3        | sky-pojo     | 子模块，存放实体类、VO、DTO等                                |
| 4        | sky-server   | 子模块，后端服务，存放配置文件、Controller、Service、Mapper等 |


sky-common模块中存放的是一些公共类，可以供其他模块使用：

| 名称        | 说明                           |
  | ----------- | ------------------------------ |
| constant    | 存放相关常量类                 |
| context     | 存放上下文类                   |
| enumeration | 项目的枚举类存储               |
| exception   | 存放自定义异常类               |
| json        | 处理json转换的类               |
| properties  | 存放SpringBoot相关的配置属性类 |
| result      | 返回结果类的封装               |
| utils       | 常用工具类                     |


sky-pojo模块中存放的是Entity、DTO、VO：

| **名称** | **说明**                                     |
  | -------- | -------------------------------------------- |
| Entity   | 实体，通常和数据库中的表对应                 |
| DTO      | 数据传输对象，通常用于程序中各层之间传递数据 |
| VO       | 视图对象，为前端展示数据提供的对象           |
| POJO     | 普通Java对象，只有属性和对应的getter和setter |


sky-server模块中存放的是配置文件、配置类、拦截器、controller、service、mapper、启动类等：

| 名称           | 说明             |
  | -------------- | ---------------- |
| config         | 存放配置类       |
| controller     | 存放controller类 |
| interceptor    | 存放拦截器类     |
| mapper         | 存放mapper接口   |
| service        | 存放service类    |
| SkyApplication | 启动类           |

数据库表的组成如下，每张表的说明：

| **序号** | **表名**      | **中文名**     |
| -------- | ------------- | -------------- |
| 1        | employee      | 员工表         |
| 2        | category      | 分类表         |
| 3        | dish          | 菜品表         |
| 4        | dish_flavor   | 菜品口味表     |
| 5        | setmeal       | 套餐表         |
| 6        | setmeal_dish  | 套餐菜品关系表 |
| 7        | user          | 用户表         |
| 8        | address_book  | 地址表         |
| 9        | shopping_cart | 购物车表       |
| 10       | orders        | 订单表         |
| 11       | order_detail  | 订单明细表     |

详见《数据库设计文档》

## 各模块详解
### sky-take-out.sky-common：存放公共类

#### sky-common.constant.AutoFillConstant：为“公共字段自动填充”提供统一的常量定义
（路径：/sky-common/src/main/java/com/sky/constant/）

AutoFillConstant类主要用于存储与“公共字段自动填充”相关的常量，具体是实体类中某些方法的名称，这些方法通常与数据库操作中的审计字段（audit fields）相关，比如创建时间、更新时间、创建用户和更新用户

所谓“公共字段自动填充”，通常是在持久化操作（如插入或更新数据库记录）时，自动为某些字段赋值，而无需业务代码显式调用
这类设计常见于使用了ORM框架（如MyBatis）的项目中，通过某种机制（比如MyBatis-Plus的MetaObjectHandler）实现字段的自动填充

定义了四个public static final String类型的常量，分别对应实体类中的setter方法名称：
- setCreateTime：设置创建时间的方法
- setUpdateTime：设置更新时间的方法
- setCreateUser：设置创建用户的方法
- setUpdateUser：设置更新用户的方法

**模块作用**
1. 标准化方法名
通过将 setCreateTime 等方法名定义为常量，避免在代码中直接使用魔法字符串（"magic string"），提高了代码的可读性和可维护性
如果将来实体类的方法名需要调整，只需修改这里的值即可，而无需改动所有使用这些方法名的地方

2. 支持自动填充机制
这些常量配合某个自动填充工具使用，例如在MyBatis-Plus中，可以通过MetaObjectHandler实现插入或更新时自动填充字段（如当前时间或当前登录用户ID）
这些常量会被用作键（key），通过反射调用实体类的setter方法来赋值

3. 解耦业务逻辑与底层实现
将方法名抽取为常量，业务代码只需关注逻辑本身，而无需关心字段填充的具体实现细节
这种设计符合“单一职责原则”和“开闭原则”，方便后续扩展或修改


#### sky-common.constant.JwtClaimsConstant：为JWT的claims提供统一的键名常量定义
（路径：/sky-common/src/main/java/com/sky/constant/）

JwtClaimsConstant类主要用于存储与JWT（JSON Web Token）中claims相关的键名常量

**模块作用**
从高级开发者的角度，这段代码的核心作用是为JWT的claims提供统一的键名常量定义，具体来说：

1. 规范化JWT键名
在使用JWT时，负载中的字段名称需要保持一致，例如，当生成一个JWT时，将用户ID存储在"userId"键下，解析JWT时，也需要通过"userId"来提取用户ID
如果在代码中直接使用字符串（如 "userId"），容易因拼写错误或不一致导致问题
将这些键名定义为常量，可以避免“魔法字符串”（magic string），提高代码的可读性和可靠性

2. 支持身份验证与授权
JWT通常用于在微服务架构或前后端分离项目中传递用户信息。这些常量表明系统中可能需要存储和传递的身份信息（如员工ID、用户名等），为认证和授权提供基础支持

3. 提高代码可维护性
如果将来需要调整某个键名（例如将"empId"改为"employeeId"），只需修改JwtClaimsConstant类中的常量值，而无需改动所有使用该键名的地方
这种集中管理的方式符合“单一变更点”原则

MessageConstant、PasswordConstant和StatusConstant类作用相近，故略


#### sky-common.context.BaseContext：提供一个线程安全的上下文管理工具
（路径：/sky-common/src/main/java/com/sky/context/）

BaseContext类存储和获取当前线程中的用户ID（或其他标识符），并提供了设置、获取和移除该值的方法
这种设计通常用于在多线程环境中维护线程隔离的上下文信息

ThreadLocal<Long>是一个泛型化的线程局部变量，用于为每个线程独立存储一个Long类型的值
ThreadLocal是Java提供的一种机制，确保每个线程拥有自己的变量副本，线程之间互不干扰，将其定义为static意味着它是类级别的，所有线程共享同一个ThreadLocal实例，但每个线程存储的值是独立的

    public static ThreadLocal<Long> threadLocal = new ThreadLocal<>();

setCurrentId方法接收一个Long类型的id参数，并通过threadLocal.set(id)将其存储到当前线程的ThreadLocal变量中
这意味着调用该方法的线程会将其上下文中的“当前ID”设置为传入的id

    public static void setCurrentId(Long id) {
        threadLocal.set(id);
    }

getCurrentId方法返回当前线程中存储在ThreadLocal中的Long值
如果当前线程从未调用过setCurrentId，则get()会返回null,因为ThreadLocal的初始值默认是null

    public static Long getCurrentId() {
    return threadLocal.get();
    }

removeCurrentId方法从当前线程的ThreadLocal中移除存储的值
这是一个清理操作，避免线程复用时（例如线程池中的线程）遗留旧数据，导致上下文信息错误

    public static void removeCurrentId() {
    threadLocal.remove();
    }

**模块作用**
1. 线程隔离的上下文管理
在多线程环境中，如Web服务器处理多个请求，每个线程需要独立的上下文信息
通过ThreadLocal，BaseContext类确保每个线程的ID是隔离的，避免并发访问时的冲突（多线程竞争）

2. 简化用户身份传递
这类设计常用于存储当前登录用户的ID，例如在一个Web应用中，用户的ID可能需要在请求处理的不同层（Controller、Service、DAO）之间传递
使用BaseContext类可以避免显式地将ID作为参数层层传递，消除了在方法调用链中显式传递用户ID的需求

3. 支持线程安全的业务逻辑
通过setCurrentId、getCurrentId和removeCurrentId，开发者可以在需要时设置上下文，在使用时获取上下文，并在完成后清理上下文，确保线程安全性和资源的正确释放


### sky-take-out.sky-server：后端服务

#### sky-server.config.WebMvcConfiguration：Spring MVC的配置类
（路径：/sky-server/src/main/java/com/sky/config/）

**类定义**
- `@Configuration`：Spring注解，标记这是一个配置类，Spring容器会扫描并加载其中的Bean定义
- `@Slf4j`：Lombok注解，自动为类生成一个SLF4J的日志对象log，便于日志记录
- `extends WebMvcConfigurationSupport`：继承Spring MVC的配置支持类，允许开发者自定义MVC相关配置（如拦截器、资源映射等）


    package com.sky.config;

    @Configuration
    @Slf4j
    public class WebMvcConfiguration extends WebMvcConfigurationSupport {

**Spring拦截器**
这个拦截器主要用于权限控制，确保只有携带有效JWT令牌的请求才能访问/admin/**下的接口，而登录接口被排除在外，允许未认证用户访问

- `@Autowired private JwtTokenAdminInterceptor jwtTokenAdminInterceptor;`：通过Spring的依赖注入，自动注入一个名为JwtTokenAdminInterceptor的拦截器实例，这个拦截器可能是自定义的，用于验证JWT令牌的合法性
- addInterceptors方法：重写了WebMvcConfigurationSupport的方法，用于注册自定义拦截器
- `registry.addInterceptor(jwtTokenAdminInterceptor)`：将注入的JWT拦截器注册到Spring MVC中
- `.addPathPatterns("/admin/**")`：指定拦截器生效的路径模式，这里表示拦截所有以/admin/开头的请求（例如/admin/user/list）
- `.excludePathPatterns("/admin/employee/login")`：排除特定的路径，表示登录接口不需要拦截，因为用户还未生成JWT令牌


    @Autowired
    private JwtTokenAdminInterceptor jwtTokenAdminInterceptor;
    
    protected void addInterceptors(InterceptorRegistry registry) {
    log.info("开始注册自定义拦截器...");
    registry.addInterceptor(jwtTokenAdminInterceptor)
    .addPathPatterns("/admin/**")
    .excludePathPatterns("/admin/employee/login");
    }

**接口文档生成**
- `@Bean public Docket docket()`：定义一个Spring Bean，返回一个Docket对象，用于配置Swagger（Knife4j）的接口文档
- `ApiInfo apiInfo`：使用 ApiInfoBuilder 创建接口文档的元信息，包括标题、版本和描述
- Docket配置：略

**静态资源映射**
- addResourceHandlers方法: 重写了WebMvcConfigurationSupport的方法，用于配置静态资源映射
- `registry.addResourceHandler("/doc.html")`：将URL路径/doc.html映射到类路径下的META-INF/resources/目录
- `registry.addResourceHandler("/webjars/**")`：将URL路径/webjars/**映射到META-INF/resources/webjars/目录


    protected void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/doc.html").addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("/webjars/**").addResourceLocations("classpath:/META-INF/resources/webjars/");
    }

**模块作用**
拦截器: 用户请求/admin/order/lis时，JwtTokenAdminInterceptor会验证请求头中的JWT令牌，确保只有合法管理员能访问
接口文档: 开发人员访问http://localhost:8080/doc.html，可以看到所有控制器接口的详细文档
资源映射: /doc.html和/webjars/**的映射保证了文档页面的正常渲染


#### sky-server.config.WebMvcConfiguration：员工管理控制器
（路径：/sky-server/src/main/java/com/sky/controller.admin/）

**类定义**
- `@RestController`：Spring注解，表示这是一个RESTful控制器，所有方法的返回值会自动序列化为JSON响应
- `@RequestMapping("/admin/employee")`：为控制器设置基础路径，所有方法都以/admin/employee开头，如/admin/employee/login
- `@Slf4j`：Lombok注解，生成SLF4J日志对象log，用于记录日志


    @RestController
    @RequestMapping("/admin/employee")
    @Slf4j
    public class EmployeeController {

**依赖注入**
- `@Autowired private EmployeeService employeeService;`：注入EmployeeService服务层接口，用于处理员工相关的业务逻辑
- `@Autowired private JwtProperties jwtProperties;`：注入JwtProperties配置类，包含JWT相关的属性，通常从配置文件如application.yml中加载


    @Autowired
    private EmployeeService employeeService;
    @Autowired
    private JwtProperties jwtProperties;

**登录接口（/login）**
- `@PostMapping("login")`：定义一个POST请求接口，路径为/admin/employee/login，用于员工登录
- `@RequestBody EmployeeLoginDTO employeeLoginDTO`：从请求体中接受JSON格式的登录数据，映射为EmployeeLoginDTO
- `log.info("员工登录：{}", employeeLoginDTO);`：记录登录请求的日志
- `Employee employee = employeeService.login(employeeLoginDTO);`：调用服务层的login方法验证登录信息，返回Employee实体对象

**生成JWT令牌**
- `Map<String, Object> claims = new HashMap<>();`：创建一个Map存储JWT的claims
- `claims.put(JwtClaimsConstant.EMP_ID, employee.getId());`：将员工ID放入claims，使用JwtClaimsConstant.EMP_ID作为键名，确保键名一致性
- `String token = JwtUtil.createJWT(...)`：调用工具类JwtUtil生成JWT令牌，传入密钥（adminSecretKey）、有效期（adminTtl）和claims

**构建响应对象**
- `EmployeeLoginVO employeeLoginVO = EmployeeLoginVO.builder()...`：使用建造者模式创建EmployeeLoginVO对象，包含员工ID、用户名、姓名和JWT令牌
- `Result.success(employeeLoginVO)`：封装成功响应，返回给客户端


    @PostMapping("/login")
    public Result<EmployeeLoginVO> login(@RequestBody EmployeeLoginDTO employeeLoginDTO) {
    log.info("员工登录：{}", employeeLoginDTO);

        Employee employee = employeeService.login(employeeLoginDTO);

        // 登录成功后，生成JWT令牌
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaimsConstant.EMP_ID, employee.getId());
        String token = JwtUtil.createJWT(
            jwtProperties.getAdminSecretKey(),
            jwtProperties.getAdminTtl(),
            claims);

        EmployeeLoginVO employeeLoginVO = EmployeeLoginVO.builder()
            .id(employee.getId())
            .userName(employee.getUsername())
            .name(employee.getName())
            .token(token)
            .build();

        return Result.success(employeeLoginVO);
    }

**退出接口（/logout）**
- @PostMapping("/logout")：定义一个POST请求接口，路径为 /admin/employee/logout，用于员工退出
- return Result.success();：返回一个简单的成功响应，不携带具体数据


    @PostMapping("/logout")
    public Result<String> logout() {
        return Result.success();
    }

**模块作用**

EmployeeController 是一个管理员端的员工管理控制器，主要功能包括：
- 员工登录：接收登录请求，验证身份，生成JWT令牌，返回员工信息和令牌
- 员工退出：处理退出请求

它是一个典型的RESTful API控制器，体现了Spring Boot中前后端分离架构的常见实践：
- 前端提交登录数据，后端验证并返回JWT
- 后续请求携带JWT进行身份认证


#### sky-server.handler.GlobalExceptionHandler：全局异常处理类
（路径：/sky-server/src/main/java/com/sky/handler/）

**类定义**
- `@RestControllerAdvice`: Spring注解，是@ControllerAdvice和@ResponseBody的组合，用于全局处理控制器层的异常，并将返回值序列化为JSON，它通常用于统一异常处理或增强控制器行为
- `@Slf4j`: Lombok注解，生成SLF4J日志对象log，用于记录异常日志

**异常处理方法**
- `@ExceptionHandler`：Spring注解，指定该方法处理特定类型的异常，这里未显式指定异常类型，但根据参数BaseException ex，它会捕获BaseException及其子类的异常
- `public Result exceptionHandler(BaseException ex)`：定义异常处理方法，参数ex是捕获的异常对象，返回值是Result类型，通常是一个封装了响应状态、消息和数据的统一返回对象
- `log.error("异常信息：{}", ex.getMessage());`：使用SLF4J记录错误日志，输出异常的详细信息（ex.getMessage()），便于调试和问题追踪
- `return Result.error(ex.getMessage());`：返回一个错误响应，包含异常消息，通常Result是一个通用返回类，可能包含状态码、消息和数据字段，这里只携带了错误消息


    @ExceptionHandler
    public Result exceptionHandler(BaseException ex){
        log.error("异常信息：{}", ex.getMessage());
        return Result.error(ex.getMessage());
    }

**模块作用**

GlobalExceptionHandler类的核心作用是作为一个全局异常处理器，统一捕获和处理项目中抛出的BaseException类型业务异常
通过全局异常处理，所有业务异常都返回一致的响应格式Result，便于前端解析，体现了统一性
异常处理逻辑与业务代码分离，控制器无需显式处理异常，提高代码简洁性，体现了解耦

- 异常捕获：拦截所有控制器层抛出的BaseException及其子类异常
- 日志记录：将异常信息记录到日志中，便于后续分析
- 统一响应：将异常转化为标准的Result对象返回给客户端，确保前后端交互的一致性


#### sky-server.interceptor.JwtTokenAdminInterceptor：JWT令牌校验拦截器
（路径：/sky-server/src/main/java/com/sky/interceptor/）

定义了一个名为JwtTokenAdminInterceptor的拦截器类，实现了Spring MVC的HandlerInterceptor接口，用于在请求处理前校验JWT令牌的合法性，确保只有携带有效令牌的请求能够访问受保护的资源

**类定义**
- `@Component`：Spring注解，将该类注册为Spring Bean，使其可以被容器管理并注入到其他组件
- `@Slf4j`：Lombok注解，生成SLF4J日志对象log，用于记录日志
- `implements HandlerInterceptor`：实现Spring MVC的HandlerInterceptor接口，提供请求拦截功能


    @Component
    @Slf4j
    public class JwtTokenAdminInterceptor implements HandlerInterceptor {

**依赖注入**
- `@Autowired private JwtProperties jwtProperties;`：注入JwtProperties配置类，包含JWT相关的属性（如令牌名称adminTokenName和密钥adminSecretKey），通常从配置文件application.yml加载


    @Autowired
    private JwtProperties jwtProperties;

**preHandle方法**

HandlerInterceptor接口的核心方法，在请求到达控制器之前执行
参数包括request（请求对象）、response（响应对象）和handler（被拦截的目标处理器）
返回boolean，决定是否放行请求（true放行，false拦截）

1. 判断拦截目标
    - `if (!(handler instanceof HandlerMethod)) { return true; }`：检查拦截到的handler是否是HandlerMethod类型（控制器方法），如果不是（如静态资源请求），直接放行，避免干扰非动态资源的访问

2. 获取令牌
   - `String token = request.getHeader(jwtProperties.getAdminTokenName());`：从请求头中获取JWT令牌，键名由jwtProperties.getAdminTokenName()提供
   - 客户端通常在请求头中携带令牌，例如`Authorization: Bearer <token>`

3. 校验令牌
   - `try { ... }`：使用try-catch块校验令牌，捕获可能的异常
   - `log.info("jwt校验:{}", token);`：记录令牌信息，便于调试
   - `Claims claims = JwtUtil.parseJWT(jwtProperties.getAdminSecretKey(), token);`：调用JwtUtil工具类解析JWT，使用管理员密钥验证令牌签名并提取声明
   - `Long empId = Long.valueOf(claims.get(JwtClaimsConstant.EMP_ID).toString());`：从claims中获取员工ID（键名由JwtClaimsConstant.EMP_ID定义），转换为Long类型
   - `log.info("当前员工id：", empId);`：记录员工ID
   - `return true;`：校验通过，放行请求

4. 处理异常
- `catch (Exception ex) { ... }`：捕获解析JWT时的异常（如令牌过期、签名无效或为空）
- `response.setStatus(401);`：设置HTTP状态码为401（未授权），通知客户端认证失败
- `return false;`：拦截请求，不允许继续访问控制器


    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    // 判断当前拦截到的是Controller的方法还是其他资源
    if (!(handler instanceof HandlerMethod)) {
    // 当前拦截到的不是动态方法，直接放行
        return true;
    }
        // 1、从请求头中获取令牌
        String token = request.getHeader(jwtProperties.getAdminTokenName());

        // 2、校验令牌
        try {
            log.info("jwt校验:{}", token);
            Claims claims = JwtUtil.parseJWT(jwtProperties.getAdminSecretKey(), token);
            Long empId = Long.valueOf(claims.get(JwtClaimsConstant.EMP_ID).toString());
            log.info("当前员工id：", empId);
            // 3、通过，放行
            return true;

        } catch (Exception ex) {
            // 4、不通过，响应401状态码
            response.setStatus(401);
            return false;
        }
    }

#### sky-server.mapper.EmployeeMapper：MyBatis注解实现数据库查询
（路径：/sky-server/src/main/java/com/sky/mapper/）

通过MyBatis的注解方式实现数据库查询操作，具体功能是根据用户名查询员工信息

**接口定义**
- `@Mapper`：MyBatis注解，标记这是一个Mapper接口，Spring Boot启动时会扫描该注解，自动生成实现类并注册为Spring Bean，无需显式配置
- `public interface EmployeeMapper`: 定义为接口，符合MyBatis的要求，MyBatis会通过动态代理生成实现类


    @Mapper
    public interface EmployeeMapper {

**查询方法**
- `@Select("select * from employee where username = #{username}")`：MyBatis注解，定义SQL查询语句
- `select * from employee`：查询employee表的所有列
- `where username = #{username}`：使用MyBatis的占位符#{}，将方法参数username动态注入到SQL中，防止SQL注入
- `Employee getByUsername(String username);`：MyBatis会自动将查询结果映射为Employee实体对象，返回给调用方


    @Select("select * from employee where username = #{username}")
    Employee getByUsername(String username);


**模块作用**

使用MyBatis注解方式定义SQL，代码简洁，无需额外的XML配置文件
类型安全，返回值为Employee对象，编译期即可检查类型一致性
EmployeeMapper模块是数据访问层的重要组件，与Spring Boot和MyBatis深度集成，提供简洁高效的数据库操作接口，这种设计体现了ORM框架的使用习惯，是典型的数据层实现方式


#### sky-server.service.EmployeeService：登录服务层接口
（路径：/sky-server/src/main/java/com/sky/service/）

定义一个名为EmployeeService的接口，其是一个服务层接口，声明了一个抽象方法login，用于处理员工登录逻辑
- 定义业务契约：声明员工登录功能的抽象方法，规定输入（EmployeeLoginDTO）和输出（Employee），为调用方和实现方提供统一规范
- 抽象业务逻辑：将登录的具体实现细节留给实现类，服务层接口只负责定义功能，符合接口隔离原则
- 支持依赖注入：作为Spring管理的服务接口，可以被控制器或其他组件注入使用


    public interface EmployeeService {
    
        /**
         * 员工登录
         * @param employeeLoginDTO
         * @return
         */
        Employee login(EmployeeLoginDTO employeeLoginDTO);
    
    }


#### sky-server.impl.EmployeeServiceImpl：EmployeeService接口的实现类
（路径：/sky-server/src/main/java/com/sky/）

定义了一个名为EmployeeServiceImpl的类，实现了EmployeeService接口，提供了员工登录的具体实现
通过查询数据库、验证用户信息并处理异常情况，最终返回登录成功的员工实体

**类定义**
`@Service`：Spring注解，将该类注册为服务层的Spring Bean，供其他组件（如控制器）注入使用
`implements EmployeeService`：实现EmployeeService接口，履行接口定义的login方法契约

    @Service
    public class EmployeeServiceImpl implements EmployeeService {

**依赖注入**
`@Autowired private EmployeeMapper employeeMapper;`：通过Spring的依赖注入，注入EmployeeMapper接口实例（由MyBatis动态生成），用于数据库操作

    @Autowired 
    private EmployeeMapper employeeMapper;

**登录方法**
- `public Employee login(EmployeeLoginDTO employeeLoginDTO)`：**实现**接口中的login方法，接收EmployeeLoginDTO参数，返回Employee对象

1. 获取输入数据：
    - `String username = employeeLoginDTO.getUsername();`：从DTO中提取用户名
    - `String password = employeeLoginDTO.getPassword();`：从DTO中提取密码

2. 查询数据库：
   - `Employee employee = employeeMapper.getByUsername(username);`：调用Mapper查询数据库，返回匹配用户名的员工实体，若无记录则返回null

3. 异常处理：
   - 账号不存在
   `if (employee == null)`：如果查询结果为空，抛出AccountNotFoundException，使用常量MessageConstant.ACCOUNT_NOT_FOUND作为错误消息
   - 密码错误
   `if (!password.equals(employee.getPassword()))`：比较输入密码与数据库中的密码（当前明文比较），若不匹配，抛出PasswordErrorException
   （后期需要进行md5加密，当前密码未加密，未来计划使用MD5加密后再比较）
   - 账号锁定
   `if (employee.getStatus() == StatusConstant.DISABLE)`：检查员工状态，若为禁用，抛出AccountLockedException

4. 返回结果：
   `return employee;`：所有验证通过后，返回员工实体对象


#### sky-server.SkyApplication：Spring Boot应用程序入口类
（路径：/sky-server/src/main/java/com/sky/）

定义了一个名为SkyApplication的类，它是Spring Boot应用程序的主类，通过注解配置Spring Boot特性，并包含main方法作为程序入口，用于启动服务

**类定义**
- `@SpringBootApplication`：Spring Boot核心注解，是以下三个注解的组合：
  - `@SpringBootConfiguration`：标记这是一个Spring配置类，等价于@Configuration
  - `@EnableAutoConfiguration`：启用Spring Boot的自动配置，根据类路径中的依赖自动配置Bean
  - `@ComponentScan`：启用组件扫描，默认扫描com.sky及其子包中的Spring组件

- `@EnableTransactionManagement`：Spring注解，开启基于注解的事务管理支持，允许在方法上使用@Transactional注解来声明事务
- `@Slf4j`：Lombok注解，生成SLF4J日志对象log，用于记录日志


    @SpringBootApplication
    @EnableTransactionManagement
    @Slf4j
    public class SkyApplication {

**主方法**
- `public static void main(String[] args)`：Java程序的标准入口方法，接收命令行参数
- `SpringApplication.run(SkyApplication.class, args);`：调用Spring Boot的SpringApplication静态方法启动应用，包括加载配置、创建Spring上下文、启动Web服务器等
  - `SkyApplication.class`：指定主类，Spring Boot以此为起点扫描配置和组件
  - `args`: 命令行参数，可用于配置
  - 该方法初始化Spring容器、加载配置、启动内嵌Web服务器（如Tomcat）等
- `log.info("server started");`：在应用启动完成后记录一条日志，表明服务已成功启动，便于监控和调试


    public static void main(String[] args) {
        SpringApplication.run(SkyApplication.class, args);
        log.info("server started");
    }

# Day2
## Nginx反向代理和负载均衡

前端发送的请求，是如何请求到后端服务的？

前端请求地址：http://localhost/api/employee/login
后端接口地址：http://localhost:8080/admin/employee/login

**Nginx反向代理**

Nginx反向代理，就是将前端发送的动态请求由Nginx转发到后端服务器

Nginx反向代理的好处：
1. 提高访问速度：因为Nginx本身可以进行缓存，如果访问的是同一接口，并且做了数据缓存，Nginx就直接可以把数据返回，不需要真正地访问服务端，从而提高访问速度
2. 进行负载均衡：所谓负载均衡，就是把大量的请求按照我们指定的方式均衡的分配给集群中的每台服务器
3. 保证后端服务安全：一般后台服务地址不会暴露，所以使用浏览器不能直接访问，可以把Nginx作为请求访问的入口，请求到达Nginx后转发到具体的服务中，从而保证后端服务的安全

Nginx反向代理的配置方式
在Nginx-1.20.2\conf中，打开Nginx配置：

    server {
        listen 80;
        server_name localhost;

        location /api/{
            proxy_pass http://localhost:8080/admin/; # 反向代理
        }
    }

以上代码表示：监听80端口号，当我们访问http://localhost:80/api/../..这样的接口时，它会通过location/api/{}这样的反向代理到http://localhost:8080/admin/

进入nginx-1.20.2\conf，打开Nginx配置

    # 反向代理，处理管理端发送的请求
    location /api/ {
    proxy_pass   http://localhost:8080/admin/;
    #proxy_pass   http://webservers/admin/;
    }

当在访问http://localhost/api/employee/login，nginx接收到请求后转到http://localhost:8080/admin/，故最终的请求地址为http://localhost:8080/admin/employee/login，和后台服务的访问地址一致

**Nginx负载均衡**
当如果服务以集群的方式进行部署时，那Nginx在转发请求到服务器时就需要做相应的负载均衡，负载均衡从本质上来说也是基于反向代理来实现的，最终都是转发请求

Nginx负载均衡的配置方式

    upstream webservers {
        server 192.168.100.128.8080;
        server 192.168.100.129:8080;
    }
    server {
        listen 80;
        server_name localhost;

        location /api/{
            proxy_pass http://webservers/admin; # 负载均衡
        }
    }

- upstream：如果代理服务器是一组服务器的话，可以使用upstream指令配置后端服务器组
- 监听80端口号，当我们访问http://localhost:80/api/.../这样的接口时，会通过location/api/{}反向代理到http://webservers/admin
  根据webservers名称找到一组服务器，根据设置的负载均衡策略（默认轮询）转发到具体的服务器

**nginx 负载均衡策略：**

| **名称**   | **说明**                         |
| ---------- |--------------------------------|
| 轮询       | 默认方式                           |
| weight     | 权重方式，默认为1，权重越高，被分配的客户端请求就越多    |
| ip_hash    | 依据IP分配方式，这样每个访客可以固定访问一个后端服务    |
| least_conn | 依据最少连接方式，把请求优先分配给连接数少的后端服务     |
| url_hash   | 依据URL分配方式，这样相同的URL会被分配到同一个后端服务 |
| fair       | 依据响应时间方式，响应时间短的服务将会被优先分配       |

具体配置方式
_轮询_

```nginx
upstream webservers{
    server 192.168.100.128:8080;
    server 192.168.100.129:8080;
}
```

_weight_

```nginx
upstream webservers{
    server 192.168.100.128:8080 weight=90;
    server 192.168.100.129:8080 weight=10;
}
```

_ip_hash_

```nginx
upstream webservers{
    ip_hash;
    server 192.168.100.128:8080;
    server 192.168.100.129:8080;
}
```

_least_conn_

```nginx
upstream webservers{
    least_conn;
    server 192.168.100.128:8080;
    server 192.168.100.129:8080;
}
```

_url_hash_

```nginx
upstream webservers{
    hash &request_uri;
    server 192.168.100.128:8080;
    server 192.168.100.129:8080;
}
```

_fair_

```nginx
upstream webservers{
    server 192.168.100.128:8080;
    server 192.168.100.129:8080;
    fair;
}
```

## 完善登录功能
**问题**：员工表中的密码是明文存储，安全性太低
解决思路：
1. 将密码加密后存储，提高安全性
2. 使用MD5加密方式对密码加密

## Swagger
Swagger是一个规范和完整的框架，用于生成、描述、调用和可视化RESTful风格的Web服务，他的主要作用是：
1. 使得前后端分离开发更加方便，有利于团队协作
2. 在线自动生成接口文档，降低后端开发人员编写接口文档的负担
3. 功能测试

knife4j是为Java MVC框架集成Swagger生成API文档的增强解决方案，前身是swagger-bootstrap-ui，取名knife4j是希望它能像一把匕首一样小巧、轻量，并且功能强悍

**使用步骤**
1. 导入knife4j的Maven坐标，在pom.xml中添加依赖


    <dependency>
        <groupId>com.github.xiaoymin</groupId>
        <artifactId>knife4j-spring-boot-starter</artifacId>
    </dependency>

2. 在配置类WebMvcConfiguration.java中加入knife4j相关配置


        @Bean
    public Docket docket() {
        ApiInfo apiInfo = new ApiInfoBuilder()
                .title("北邮外卖项目接口文档")
                .version("2.0")
                .description("北邮外卖项目接口文档")
                .build();
        Docket docket = new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo)
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.sky.controller"))
                .paths(PathSelectors.any())
                .build();
        return docket;
    }

3. 设置静态资源映射，否则接口文档页面无法访问WebMvcConfiguration.java


        protected void addResourceHandlers(ResourceHandlerRegistry registry) {
            registry.addResourceHandler("/doc.html").addResourceLocations("classpath:/META-INF/resources/");
            registry.addResourceHandler("/webjars/**").addResourceLocations("classpath:/META-INF/resources/webjars/");
        }

4. 访问测试，接口文档访问路径为http://ip:port/doc.html（http://localhost:8080/doc.html）


**Swagger常用注解**

| **注解**          | **说明**                                               |
| ----------------- | ------------------------------------------------------ |
| @Api              | 用在类上，例如Controller，表示对类的说明               |
| @ApiModel         | 用在类上，例如entity、DTO、VO                          |
| @ApiModelProperty | 用在属性上，描述属性信息                               |
| @ApiOperation     | 用在方法上，例如Controller的方法，说明方法的用途、作用 |

使用上述注解生成可读性更好的接口文档
- 在sky-pojo模块中，EmployeeLoginDTO.java：


    package com.sky.dto;
    
    import io.swagger.annotations.ApiModel;
    import io.swagger.annotations.ApiModelProperty;
    import lombok.Data;
    
    import java.io.Serializable;
    
    @Data
    @ApiModel(description = "员工登录时传递的数据模型")
    public class EmployeeLoginDTO implements Serializable {
    
        @ApiModelProperty("用户名")
        private String username;
    
        @ApiModelProperty("密码")
        private String password; 
    }

-在sky-pojo模块中，EmployeeLoginVo.java：


    package com.sky.vo;
    
    import io.swagger.annotations.ApiModel;
    import io.swagger.annotations.ApiModelProperty;
    import lombok.AllArgsConstructor;
    import lombok.Builder;
    import lombok.Data;
    import lombok.NoArgsConstructor;
    
    import java.io.Serializable;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @ApiModel(description = "员工登录返回的数据格式")
    public class EmployeeLoginVO implements Serializable {
    
        @ApiModelProperty("主键值")
        private Long id;
    
        @ApiModelProperty("用户名")
        private String userName;
    
        @ApiModelProperty("姓名")
        private String name;
    
        @ApiModelProperty("jwt令牌")
        private String token;
    }

- 在sky-server模块中，EmployeeController.admin：


# Day2

## 新增员工
### 需求分析和设计
后台系统中可以管理员工信息，通过新增员工来添加后台系统用户
当填写完表单信息，点击"保存"按钮后, 会提交该表单的数据到服务端，在服务端中需要接受数据，然后将数据保存至数据库中

**注意事项**
1. 账号必须是唯一的
2. 手机号为合法的11位手机号码
3. 身份证号为合法的18位身份找号码
4. 密码默认为123456

**接口设计**
- 管理端发出的请求，统一使用/admin作为前缀
- 用户端发出的请求，统一使用/user作为前缀

**表设计**
新增员工，其实就是将我们新增页面录入的员工数据插入到employee表

| **字段名**  | **数据类型** | **说明**     | **备注**    |
| ----------- | ------------ | ------------ | ----------- |
| id          | bigint       | 主键         | 自增        |
| name        | varchar(32)  | 姓名         |             |
| username    | varchar(32)  | 用户名       | 唯一        |
| password    | varchar(64)  | 密码         |             |
| phone       | varchar(11)  | 手机号       |             |
| sex         | varchar(2)   | 性别         |             |
| id_number   | varchar(18)  | 身份证号     |             |
| status      | Int          | 账号状态     | 1正常 0锁定 |
| create_time | Datetime     | 创建时间     |             |
| update_time | datetime     | 最后修改时间 |             |
| create_user | bigint       | 创建人id     |             |
| update_user | bigint       | 最后修改人id |             |

其中，employee表中的status字段已经设置了默认值1，表示状态正常

### 代码开发
#### 设计DTO类
根据新增员工接口设计对应的DTO
当前端提交的数据和实体类中对应的属性差别比较大时，建议使用DTO来封装数据

前端传递参数列表：

| 名称       | 类型      | 是否必填 | 默认值     | 其他信息      |
|------------|-----------|----------|------------|---------------|
| id         | integer   | 必填     |            | format: int64 |
| idNumber   | string    | 必填     |            |               |
| name       | string    | 必填     |            |               |
| phone      | string    | 必填     |            |               |
| sex        | string    | 必填     |            | 性别          |
| username   | string    | 必填     |            | 用户名        |

由于上述传入参数和实体类有较大差别，所以自定义DTO类

    package com.sky.dto;
    
    import lombok.Data;
    import java.io.Serializable;
    
    @Data
    public class EmployeeDTO implements Serializable {
    
        private Long id;
    
        private String username;
    
        private String name;
    
        private String phone;
    
        private String sex;
    
        private String idNumber;
    }

#### Controller层
在EmployeeController中创建新增员工方法，接收前端提交的参数

    /**
     * 新增员工
     * @param employeeDTO
     * @return
     */
    @PostMapping
    @ApiOperation("新增员工")
    public Result save(@RequestBody EmployeeDTO employeeDTO) {
        log.info("新增员工：{}", employeeDTO);
        employeeService.save(employeeDTO);
        return Result.success();
    }

Result类（com/sky/result/Result.java）定义了后端统一返回结果格式

#### Service层接口
在EmployeeService接口中声明新增员工方法

    /**
     * 新增员工
     * @param employeeDTO
     */
    void save(EmployeeDTO employeeDTO);

#### Service层实现类
在EmployeeServiceImpl中实现新增员工方法

        @Override
    public void save(EmployeeDTO employeeDTO) {
        Employee employee = new Employee();

        // 对象属性拷贝
        BeanUtils.copyProperties(employeeDTO, employee);

        // 设置账号的状态，默认正常状态，1表示正常，0表示锁定
        employee.setStatus(StatusConstant.ENABLE);

        // 设置密码，默认密码为123456
        employee.setPassword(DigestUtils.md5DigestAsHex(PasswordConstant.DEFAULT_PASSWORD.getBytes()));

        // 设置当前记录的创建时间和修改时间
        employee.setCreateTime(LocalDateTime.now());
        employee.setUpdateTime(LocalDateTime.now());

        // 设置当前记录创建人ID和修改人ID
        empolyee.setCreateUser(10L); // TODO:后续修改
        empolyee.setUpdateUser(10L);

        employeeMapper.insert(employee); // TODO:后续定义
    }

在sky-common模块com.sky.constant包下已定义StatusConstant.java

    package com.sky.constant;

    /**
    * 状态常量，启用或者禁用
    */
    public class StatusConstant {
        //启用
        public static final Integer ENABLE = 1;
    
        //禁用
        public static final Integer DISABLE = 0;
    }

#### Mapper层
在EmployeeMapper中声明insert方法

    /**
     * 插入员工数据
     * @param employee
     */
    @Insert("insert into employee(name, username, password, phone, sex, id_number, create_time, create_user, update_user, status)"
    + "values " + "(#{name}, #{username}, #{phone}, #{sex}, #{idNumber}, #{createTime}, #{updateTime}, #{createUser}, #{updateUser}, #{status})")
    void insert(Employee employee);
    

在application.yml中已开启驼峰命名，故id_number和idNumber可对应

    mybatis:
    #mapper配置文件
    mapper-locations: classpath:mapper/*.xml
    type-aliases-package: com.sky.entity
    configuration:
    #开启驼峰命名
    map-underscore-to-camel-case: true

### 功能测试
#### 通过接口文档测试
启动服务，访问http://localhost:8080/doc.html，进入新增员工接口
初次调试时由于JWT令牌校验失败，导致EmployeeController的save方法没有被调用，需要调用员工登录接口获得一个合法的JWT令牌，并将合法的JWT令牌添加到全局参数中

### 代码完善
目前，程序存在的问题主要有两个：
- 当录入的用户名已在表中时，抛出异常后没有进行处理
- 新增员工时，创建人ID和修改人ID为固定值

**完善问题一**
在employee表中，username已经添加了唯一约束，不能重复，通过全局异常处理器来处理

进入到sky-server模块，com/sky/handler/路径下，GlobalExceptionHandler.java添加方法

    /**
     * 处理SQL异常
     *
     * @param ex
     * @return
     */
    @ExceptionHandler
    public Result exceptionHandler(SQLIntegrityConstraintViolationException ex) {
        // 重复输入键值'employee.idx_username'
        String message = ex.getMessage();
        if (message.contains("重复输入键值")) {
            String[] split = message.split(" ");
            String username = split[2];
            String msg = username + MessageConstant.ALREADY_EXISTS;
            return Result.error(msg);
        } else {
            return Result.error(message);
        }
    }

进入到sky-common模块，在MessageConstant.java添加

    public static final String ALREADY_EXISTS = "已存在";


**完善问题二**
新增员工时，创建人ID和修改人ID设置为固定值，需要通过某种方式动态获取当前登录员工的ID
需要通过基于JWT（JSON Web Token）的动态方式认证和授权流程：
- 首先，用户通过“用户认证”模块进行身份验证，生成“本地JWT Token”
- 随后，该Token被发送到“授权服务器”进行验证，生成“生成JWT Token”
- 在“请求拦截器”中，系统会检查请求头中携带的JWT Token，并将其发送到“授权服务”进行验证
- 如果验证通过，会返回“验证成功”结果，并允许访问受保护的资源
- 如果验证失败，则返回“验证失败”并拒绝访问
- 员工登录成功后会生成JWT令牌并响应给前端


    public class EmployeeController {
        @Autowired
        private EmployeeService employeeService;
        @Autowired
        private JwtProperties jwtProperties;
    
        /**
         * 登录
         *
         * @param employeeLoginDTO
         * @return
         */
        @PostMapping("/login")
        @ApiOperation(value = "员工登录")
        public Result<EmployeeLoginVO> login(@RequestBody EmployeeLoginDTO employeeLoginDTO) {
            //.........
    
            //登录成功后，生成jwt令牌
            Map<String, Object> claims = new HashMap<>();
            claims.put(JwtClaimsConstant.EMP_ID, employee.getId());
            String token = JwtUtil.createJWT(
                    jwtProperties.getAdminSecretKey(),
                    jwtProperties.getAdminTtl(),
                    claims);

            //............
            return Result.success(employeeLoginVO);
    }

后续请求中，前端会携带JWT令牌，通过JWT令牌可以解析出当前登录员工ID：
具体见JwtTokenAdminInterceptor.java

**ThreadLocal**
ThreadLocal并不是一个Thread，而是Thread的局部变量
ThreadLocal为每个线程提供单独一份存储空间，具有线程隔离的效果，只有在线程内才能获取到对应的值，线程外则不能访问

- `public void set(T value)`：设置当前线程的线程局部变量的值
- `public T get()`：返回当前线程所对应的线程局部变量的值
- `public void remove()`：移除当前线程的线程局部变量

对ThreadLocal有了一定认识后，接下来继续解决问题二
【图】

在sky-common模块已经封装了ThreadLocal操作的工具类

    package com.sky.context;

    public class BaseContext {
    
        public static ThreadLocal<Long> threadLocal = new ThreadLocal<>();
    
        public static void setCurrentId(Long id) {
            threadLocal.set(id);
        }
    
        public static Long getCurrentId() {
            return threadLocal.get();
        }
    
        public static void removeCurrentId() {
            threadLocal.remove();
        }
    
    }

在拦截器中解析出当前登录员工ID，并放入线程局部变量中：

    // 2、校验令牌
    try {
        log.info("jwt校验:{}", token);
        Claims claims = JwtUtil.parseJWT(jwtProperties.getAdminSecretKey(), token);
        Long empId = Long.valueOf(claims.get(JwtClaimsConstant.EMP_ID).toString());
        log.info("当前员工id：", empId);

        BaseContext.setCurrentId(empId); // 新增：将用户ID存储到ThreadLoacl 

        // 3、通过，放行
        return true;
    } catch (Exception ex) {
        //4、不通过，响应401状态码
        response.setStatus(401);
        return false;
    }

在Service中获取线程局部变量中的值

        // 设置当前记录创建人ID和修改人ID
        // 新修改
        employee.setCreateUser(BaseContext.getCurrentId());
        employee.setUpdateUser(BaseContext.getCurrentId());
        
        employeeMapper.insert(employee);

## 员工分页查询
系统中的员工很多的时候，如果在一个页面中全部展示出来会显得比较乱，不便于查看，所以一般的系统中都会以分页的方式来展示列表数据
而在我们的分页查询页面中，除了分页条件以外，还有一个查询条件"员工姓名"

**业务规则**
- 根据页码展示员工信息
- 每页展示10条数据
- 分页查询时可以根据需要输入员工姓名进行查询

注意：
- 请求参数类型为Query，不是json格式提交，在路径后直接拼接/admin/employee/page?name=zhangsan
- 返回数据中records数组中使用Employee实体类对属性进行封装

**设计DTO类**
根据请求参数进行封装，在sky-pojo模块中，EmployeePageQueryDTO类：

    @Data
    public class EmployeePageQueryDTO implements Serializable {
    
        // 员工姓名
        private String name;
    
        // 页码
        private int page;
    
        // 每页显示记录数
        private int pageSize;

    }

**封装PageResult**
后面所有的分页查询统一封装为PageResult对象

    /**
     * 封装分页查询结果
     */
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public class PageResult implements Serializable {
    
        private long total; // 总记录数
    
        private List records; // 当前页数据集合
    
    }

员工信息分页查询后端返回的对象类型为Result


    @Data
    public class Result<T> implements Serializable {
    
        private Integer code; // 编码：1成功，0和其它数字为失败
        private String msg; // 错误信息
        private T data; // 数据
        
        public static <T> Result<T> success() {
            Result<T> result = new Result<T>();
            result.code = 1;
            return result;
        }
        
        public static <T> Result<T> success(T object) {
            Result<T> result = new Result<T>();
            result.data = object;
            result.code = 1;
            return result;
        }
        
        public static <T> Result<T> error(String msg) {
            Result result = new Result();
            result.msg = msg;
            result.code = 0;
            return result;
        } 
    }

**Controller层**
在sky-server模块com.sky.controller.admin.EmployeeController中添加分页查询方法

    /**
     * 员工分页查询
     * @param employeePageQueryDTO
     * @return
     */
    @GetMapping("/Page")
    @ApiOperation("员工分页查询")
    public Result<PageResult> page(EmployeePageQueryDTO employeePageQueryDTO) {
        log.info("员工分页查询，参数为：{}", employeePageQueryDTO);
        PageResult pageResult = employeeService.pageQuery(employeePageQueryDTO); // TODO
        return Result.success(pageResult);
    }

**Service层接口**
在EmployeeService接口中声明pageQuery方法

    /**
     * 分页查询
     * @param employeePageQueryDTO
     * @return
     */
    PageResult pageQuery(EmployeePageQueryDTO employeePageQueryDTO);

**Service层实现类**
在EmployeeServiceImpl中实现pageQuery方法

    public PageResult pageQuery(EmployeePageQueryDTO employeePageQueryDTO) {
        // select * from employee limit 0, 10
        // 开始分页查询
        PageHelper.startPage(employeePageQueryDTO.getPage(), employeePageQueryDTO.getPageSize());

        Page<Employee> page = employeeMapper.pageQuery(employeePageQueryDTO);//后续定义

        long total = page.getTotal();
        List<Employee> records = page.getResult();

        return new PageResult(total, records);
    }

此处使用Mybatis的分页插件PageHelper来简化分页代码的开发，底层基于Mybatis的拦截器实现，故在pom.xml文中添加依赖

    <dependency>
        <groupId>com.github.pagehelper</groupId>
        <artifactId>pagehelper-spring-boot-starter</artifactId>
        <version>${pagehelper}</version>
    </dependency>

**Mapper层**
在EmployeeMapper中声明pageQuery方法

    Page<Employee> pageQuery(EmployeePageQueryDTO employeePageDTO);

在src/main/resources/mapper/EmployeeMapper.xml中编写SQL

    <select id="pageQuery" resultType="com.sky.entity.Employee">
        select * from employee
        <where>
            <if test="name != null and name != ''">
                and name like concat('%', #{name}, '%')
            </if>>
        </where>
        >
        order by create_time desc
    </select>

