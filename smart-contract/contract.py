from pyteal import *

ADMIN_KEY = Bytes("admin")
PUBLISH_DID_SELECTOR = MethodSignature("publish_did(byte[32],uint64,string)void")
UPDATE_STATUS_SELECTOR = MethodSignature("update_status(byte[32],uint8)void")

DID_STATUS_READY = Bytes("base16", "01")
METADATA_STATUS_OFFSET = Int(16)


def approval_program():
    on_create = Seq([
        App.globalPut(ADMIN_KEY, Txn.sender()),
        Approve(),
    ])

    is_admin = Txn.sender() == App.globalGet(ADMIN_KEY)

    subject_key = Txn.application_args[1]  # raw Ed25519 public key, 32 bytes
    is_abi_publish = Txn.application_args[0] == PUBLISH_DID_SELECTOR
    is_abi_update = Txn.application_args[0] == UPDATE_STATUS_SELECTOR

    raw_data_key = Txn.application_args[2]
    data_key = If(is_abi_publish, raw_data_key, raw_data_key)
    raw_document = Txn.application_args[3]
    document = If(
        is_abi_publish,
        Extract(raw_document, Int(2), Len(raw_document) - Int(2)),
        raw_document,
    )
    metadata = Concat(
        data_key,              # metadata[0] start data box uint64
        data_key,              # metadata[1] end data box uint64
        DID_STATUS_READY,      # metadata[2] status ready/resolvable
        Itob(Len(document)),   # metadata[3] final box byte length
    )

    def write_box(box_name, data):
        existing_length = App.box_length(box_name)
        return Seq([
            existing_length,
            If(existing_length.hasValue()).Then(
                Pop(App.box_delete(box_name))
            ),
            Assert(App.box_create(box_name, Len(data))),
            App.box_replace(box_name, Int(0), data),
        ])

    # did:algo app namespace publication:
    # metadata box name = subject public key (32 bytes)
    # data box name = uint64 key (8 bytes)
    on_publish_did = Seq([
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(4)),
        Assert(Len(subject_key) == Int(32)),
        Assert(Len(data_key) == Int(8)),
        write_box(subject_key, metadata),
        write_box(data_key, document),
        Approve(),
    ])

    status_value = Txn.application_args[2]
    metadata_length = App.box_length(subject_key)
    on_update_status = Seq([
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(3)),
        Assert(Len(subject_key) == Int(32)),
        Assert(Len(status_value) == Int(1)),
        metadata_length,
        Assert(metadata_length.hasValue()),
        App.box_replace(subject_key, METADATA_STATUS_OFFSET, status_value),
        Approve(),
    ])

    program = Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.DeleteApplication, Return(is_admin)],
        [Txn.on_completion() == OnComplete.UpdateApplication, Return(is_admin)],
        [Txn.application_args[0] == Bytes("PUBLISH_DID"), on_publish_did],
        [Txn.application_args[0] == Bytes("UPDATE_STATUS"), on_update_status],
        [Txn.application_args[0] == PUBLISH_DID_SELECTOR, on_publish_did],
        [Txn.application_args[0] == UPDATE_STATUS_SELECTOR, on_update_status],
    )
    return program


def clear_state_program():
    return Approve()


if __name__ == "__main__":
    with open("approval.teal", "w") as f:
        f.write(compileTeal(approval_program(), mode=Mode.Application, version=8))
    with open("clear.teal", "w") as f:
        f.write(compileTeal(clear_state_program(), mode=Mode.Application, version=8))
    print("OK : approval.teal et clear.teal generes")
