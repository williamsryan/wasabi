(module
  (type (;0;) (func))
  (type (;1;) (func (param i32)))
  (type (;2;) (func (param i32 i32) (result i32)))
  (type (;3;) (func (result i32)))
  (type (;4;) (func (param i32) (result i32)))
  (import "env" "print" (func (;0;) (type 1)))
  (func (;1;) (type 0))
  (func (;2;) (type 0)
    i32.const 1
    call 0)
  (func (;3;) (type 0)
    i32.const 2
    call 0)
  (func (;4;) (type 0)
    i32.const 0
    i32.load offset=1040
    call_indirect (type 0))
  (func (;5;) (type 1) (param i32)
    i32.const 1024
    local.get 0
    call 8
    drop)
  (func (;6;) (type 0)
    block  ;; label = @1
      i32.const 3
      i32.eqz
      br_if 0 (;@1;)
      call 1
    end)
  (func (;7;) (type 2) (param i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          local.get 0
          i32.xor
          i32.const 3
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load8_u
          local.set 2
          br 1 (;@2;)
        end
        block  ;; label = @3
          local.get 1
          i32.const 3
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          loop  ;; label = @4
            local.get 0
            local.get 1
            i32.load8_u
            local.tee 2
            i32.store8
            local.get 2
            i32.eqz
            br_if 3 (;@1;)
            local.get 0
            i32.const 1
            i32.add
            local.set 0
            local.get 1
            i32.const 1
            i32.add
            local.tee 1
            i32.const 3
            i32.and
            br_if 0 (;@4;)
          end
        end
        local.get 1
        i32.load
        local.tee 2
        i32.const -1
        i32.xor
        local.get 2
        i32.const -16843009
        i32.add
        i32.and
        i32.const -2139062144
        i32.and
        br_if 0 (;@2;)
        loop  ;; label = @3
          local.get 0
          local.get 2
          i32.store
          local.get 1
          i32.load offset=4
          local.set 2
          local.get 0
          i32.const 4
          i32.add
          local.set 0
          local.get 1
          i32.const 4
          i32.add
          local.set 1
          local.get 2
          i32.const -1
          i32.xor
          local.get 2
          i32.const -16843009
          i32.add
          i32.and
          i32.const -2139062144
          i32.and
          i32.eqz
          br_if 0 (;@3;)
        end
      end
      local.get 0
      local.get 2
      i32.store8
      local.get 2
      i32.const 255
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 0
        local.get 1
        i32.load8_u offset=1
        local.tee 2
        i32.store8 offset=1
        local.get 0
        i32.const 1
        i32.add
        local.set 0
        local.get 1
        i32.const 1
        i32.add
        local.set 1
        local.get 2
        br_if 0 (;@2;)
      end
    end
    local.get 0)
  (func (;8;) (type 2) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    call 7
    drop
    local.get 0)
  (func (;9;) (type 3) (result i32)
    i32.const 1060)
  (func (;10;) (type 3) (result i32)
    global.get 0)
  (func (;11;) (type 1) (param i32)
    local.get 0
    global.set 0)
  (func (;12;) (type 4) (param i32) (result i32)
    (local i32 i32)
    global.get 0
    local.get 0
    i32.sub
    i32.const -16
    i32.and
    local.tee 1
    global.set 0
    local.get 1)
  (table (;0;) 4 4 funcref)
  (memory (;0;) 256 256)
  (global (;0;) (mut i32) (i32.const 66608))
  (export "memory" (memory 0))
  (export "foo" (func 2))
  (export "bar" (func 3))
  (export "baz" (func 4))
  (export "setX" (func 5))
  (export "__indirect_function_table" (table 0))
  (export "_initialize" (func 6))
  (export "__errno_location" (func 9))
  (export "stackSave" (func 10))
  (export "stackRestore" (func 11))
  (export "stackAlloc" (func 12))
  (elem (;0;) (i32.const 1) func 2 3 1)
  (data (;0;) (i32.const 1024) "hello\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\02\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"))
